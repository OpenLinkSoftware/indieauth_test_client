package client

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"golang.org/x/oauth2"

	"github.com/cblakeley/indieauth/common"
	"github.com/google/uuid"
)

var gClient *Client

var (
	ErrCodeNotFound  error = errors.New("code not found")
	ErrStateNotFound error = errors.New("state not found")
	ErrInvalidState  error = errors.New("state does not match")
	ErrInvalidIssuer error = errors.New("issuer does not match")
)

// Client is a IndieAuth client. As a client, you want to authenticate other users
// to log into onto your website.
//
// AuthResponseOpt indicates the required response (as set in the UI)
// when exchanging an authorization code:
// - profile URL response (See IA spec section 5.3.2)
// - access token response (See IA spec section 5.3.3)
// - profile information (See IA spec section 5.3.4)
// Permitted values:
// "access_token" : Access token and user profile information
// "user_profile" : User profile URL only
// "user_profile_url_only" : User profile URL and profile information

type Client struct {
	Client *http.Client

	ClientID        string
	RedirectURL     string
	AuthData        *AuthInfo
	SessionID       string
	AuthResponseOpt string
}

type AuthInfo struct {
	common.Metadata
	Me           string
	State        string
	CodeVerifier string
}

type Profile struct {
	Me      string `json:"me"`
	Profile struct {
		Name  string `json:"name"`
		URL   string `json:"url"`
		WebID string `json:"webid"`
		Photo string `json:"photo"`
		Email string `json:"email"`
	} `json:"profile"`
}

type LoginFormParams struct {
	IsLoggedIn bool
	Me         string
}

type ErrorForDisplay struct {
	ErrorMsg string
}

// NewClient creates a new Client from the provided clientID and redirectURL. If
// no httpClient is given, http.DefaultClient will be used.
func NewClient(clientID, redirectURL string, httpClient *http.Client) *Client {
	c := &Client{
		ClientID:    clientID,
		RedirectURL: redirectURL,
	}

	if httpClient != nil {
		c.Client = httpClient
	} else {
		// c.Client = http.DefaultClient
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{
				Renegotiation: tls.RenegotiateFreelyAsClient,
			},
		}
		c.Client = &http.Client{Transport: tr}
	}

	return c
}

func StartHttpServer(cmd string, hostname string, port string, certFile string, keyFile string) {
	gClient = NewClient(
		fmt.Sprintf("https://%s:%s", hostname, port),
		fmt.Sprintf("https://%s:%s/callback", hostname, port),
		nil)

	currentDir, _ := os.Getwd()
	mux := http.NewServeMux()

	mux.HandleFunc("/", LoginForm)
	mux.HandleFunc("/indieauth-login", LoginHandler)
	mux.HandleFunc("/indieauth-logout", LogoutHandler)
	mux.HandleFunc("/callback", CallbackHandler)

	files := http.FileServer(http.Dir(currentDir + "/public"))
	mux.Handle("/static/", http.StripPrefix("/static/", files))

	fmt.Printf("Starting %s https server on %s:%s\n", cmd, hostname, port)

	err := http.ListenAndServeTLS(":"+port, certFile, keyFile, mux)
	if err != nil {
		log.Fatal("ERROR: StartHttpServer(): ListenAndServeTLS() failed: ", err)
	}
}

// Login form exposed by root ('/') endpoint.
func LoginForm(w http.ResponseWriter, req *http.Request) {
	isLoggedIn := false
	me := ""
	sessionId, err := session(w, req)
	if err == nil && len(sessionId) > 0 {
		isLoggedIn = true
		me = gClient.AuthData.Me
	}
	p := LoginFormParams{IsLoggedIn: isLoggedIn, Me: me}

	t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/login-form.html") // FIX ME for production deployment
	if t_err != nil {
		// template parsing error is irrecoverable. Indicates a coding error.
		pc, file, line, _ := runtime.Caller(0)
		fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
		os.Exit(1)
	}
	t.Execute(w, p)
}

func LoginHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("LoginHandler():\n")

	var scope string

	req.ParseForm()

	// Get the parameters received from the login form.
	//
	// Only 'profile' is required by the spec.
	// 'authResponseOpt' is specific to the test login form and
	// used to exercise the different options for 'scope'.
	profile := req.Form["url"][0]
	authResponseOpt := req.Form["authResponseOpt"][0]

	// scope:
	// "": Only the user's profile URL may be returned, not an access token
	// "profile": Triggers issuing of an access token and requests access to
	//            the user's default profile information which includes: name, photo, url.
	// "email": Requests the user's email address.
	//          Cannot be requested on its own, it must accompany "profile".
	// "offline_access": Requests a refresh token.

	switch authResponseOpt {
	case "user_profile":
		scope = "profile email"
	case "access_token":
		scope = "profile email offline_access"
	case "user_profile_url_only":
		fallthrough
	default:
		scope = ""
	}

	// Canonicalize the received user profile URL
	profile = CanonicalizeURL(profile)

	// Validate the profile URL according to the specification.
	err := IsValidProfileURL(profile)
	if err != nil {
		t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/error.html") // FIX ME for production deployment
		if t_err != nil {
			pc, file, line, _ := runtime.Caller(0)
			fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
			os.Exit(1)
		}
		t.Execute(w, ErrorForDisplay{ErrorMsg: err.Error()})
		return
	}

	// Obtain the authentication information and redirect URL
	authData, redirect, err := gClient.Authenticate(profile, scope)
	if err != nil {
		t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/error.html") // FIX ME for production deployment
		if t_err != nil {
			pc, file, line, _ := runtime.Caller(0)
			fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
			os.Exit(1)
		}
		t.Execute(w, ErrorForDisplay{ErrorMsg: err.Error()})
		return
	}

	// The client should now store authData because it will be used to verify the callback.
	// You can store it, for example, in a database or cookie.
	//
	// See also https://indieauth.spec.indieweb.org/#authorization
	// The sequence diagram shows transition "Client initiates login session and the user is logged in"
	//
	// https://indieweb.org/IndieAuth#How_it_works
	// IndieAuth can be used to implement OAuth2 login.

	sessionID := uuid.New().String()
	cookie := http.Cookie{
		Name:     "indie_auth_client_cookie",
		Value:    sessionID,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)

	// TO DO:
	// Store the client auth data and session ID in an in-memory data structure.
	// e.g. a map keyed on session ID.
	// Whatever it is should support multiple clients.
	// At the moment we have a single global var gClient.
	// Multiple browsers using this IndieAuth client will compete for and
	// overwrite this single global var.

	gClient.AuthData = authData
	gClient.SessionID = sessionID
	gClient.AuthResponseOpt = authResponseOpt

	// Redirect the user to the IndieAuth server's authorize endpoint.
	http.Redirect(w, req, redirect, http.StatusTemporaryRedirect)
}

func LogoutHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("LogoutHandler():\n")
	sessionId, err := session(w, req)
	if err == nil && len(sessionId) > 0 {
		// Clear the cookie.
		//
		// Clearing the cookie only logs the user out of the IndieAuth client (Relying Party).
		// It doesn't log the user out of the IndieAuth server (Authorization server).
		// The IndieAuth spec makes no mention of RP-initiated logout, but this is what is needed
		// to also log the user out of the IndieAuth server.

		expired := time.Now().Add(-7 * 24 * time.Hour)
		cookie := http.Cookie{
			Name:     "indie_auth_client_cookie",
			Value:    "expired",
			HttpOnly: true,
			Expires:  expired,
		}
		http.SetCookie(w, &cookie)

		gClient.SessionID = ""
	}
	http.Redirect(w, req, "/", http.StatusSeeOther)
}

func CallbackHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Printf("CallbackHandler()\n")
	authData := gClient.AuthData

	if err := AuthReqServerError(req); err != nil {
		fmt.Printf("ERROR: CallbackHandler(): AuthReqServerError() reported error: %s\n", err)
		t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/error.html") // FIX ME for production deployment
		if t_err != nil {
			pc, file, line, _ := runtime.Caller(0)
			fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
			os.Exit(1)
		}
		t.Execute(w, ErrorForDisplay{ErrorMsg: err.Error()})
		return
	}

	// Validate the received callback parameters

	code, err := gClient.ValidateCallback(authData, req)
	if err != nil {
		fmt.Printf("ERROR: CallbackHandler(): ValidateCallback() failed: %s\n", err)
		t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/error.html") // FIX ME for production deployment
		if t_err != nil {
			pc, file, line, _ := runtime.Caller(0)
			fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
			os.Exit(1)
		}
		t.Execute(w, ErrorForDisplay{ErrorMsg: err.Error()})
		return
	}

	// Now that you have the code, you have to redeem it. You can either use FetchProfile to
	// redeem it by the users' profile or GetToken.
	//
	// GetToken exchanges the code for an oauth2.Token based on the provided information.
	// It returns the token and an oauth2.Config object which can be used to create an http
	// client that uses the token on future requests.
	//
	// Note that token.Raw may contain other information returned by the server, such as
	// "Me", "Profile" and "Scope".

	if gClient.AuthResponseOpt == "access_token" {
		// Use GetToken()
		token, oauth2, err := gClient.GetToken(authData, code)
		if err != nil {
			fmt.Printf("ERROR: CallbackHandler(): GetToken() failed: %s\n", err)
			t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/error.html") // FIX ME for production deployment
			if t_err != nil {
				pc, file, line, _ := runtime.Caller(0)
				fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
				os.Exit(1)
			}
			t.Execute(w, ErrorForDisplay{ErrorMsg: err.Error()})
			return
		}

		exchangeResponse := CodeExchangeResponse{}
		exchangeResponse.GetTokenContents(token)

		fmt.Printf("CallbackHandler(): Retrieved access token\n")
		fmt.Printf("CallbackHandler(): oauth2: %#v\n", oauth2)
		fmt.Printf("CallbackHandler(): token: %#v\n", token)
		fmt.Printf("CallbackHandler(): exchangeResponse: %#v\n", exchangeResponse)

		t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/login-ok.html") // FIX ME for production deployment
		if t_err != nil {
			pc, file, line, _ := runtime.Caller(0)
			fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
			os.Exit(1)
		}
		t.Execute(w, exchangeResponse)

		// -----------------------------------------------------------
		// Placeholder for using the token to create a new httpClient
		// to access a protected resource using the access token.
		// httpClient := oauth2.Client(context.Background(), token)
		// -----------------------------------------------------------

	} else if gClient.AuthResponseOpt == "user_profile_url_only" || gClient.AuthResponseOpt == "user_profile" {
		// Use FetchProfile()
		profile, err := gClient.FetchProfile(authData, code)
		if err != nil {
			fmt.Printf("ERROR: CallbackHandler(): FetchProfile() failed: %s\n", err)
			t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/error.html") // FIX ME for production deployment
			if t_err != nil {
				pc, file, line, _ := runtime.Caller(0)
				fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
				os.Exit(1)
			}
			t.Execute(w, ErrorForDisplay{ErrorMsg: err.Error()})
			return
		}

		fmt.Printf("CallbackHandler(): Retrieved profile via authorize endpoint\n")
		fmt.Printf("CallbackHandler(): profile: %#v\n", profile)

		// No token response, only Me and optional profile info.
		// But use CodeExchangeResponse to receive and display this info.
		exchangeResponse := CodeExchangeResponse{}
		exchangeResponse.Profile = *profile

		fmt.Printf("CallbackHandler(): exchangeResponse: %#v\n", exchangeResponse)

		t, t_err := template.ParseFiles(common.IndieAuthRootDir() + "/client/login-ok.html") // FIX ME for production deployment
		if t_err != nil {
			pc, file, line, _ := runtime.Caller(0)
			fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, t_err)
			os.Exit(1)
		}
		t.Execute(w, exchangeResponse)

	} else {
		err := fmt.Errorf("Unknown AuthResponseOpt value (%s)", gClient.AuthResponseOpt)
		pc, file, line, _ := runtime.Caller(0)
		fmt.Printf("ERROR in %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, err)
		os.Exit(1)
	}

}

// Authenticate takes a profile URL and the desired scope, discovers the required endpoints,
// generates a random scope and code challenge (using method SHA256), and builds the authorization
// URL. It returns the authorization info, redirect URI and an error.
//
// The returned AuthInfo should be stored by the caller of this function in such a way that it
// can be retrieved to validate the callback.
func (c *Client) Authenticate(profile, scope string) (*AuthInfo, string, error) {
	fmt.Printf("Authenticate():\n")
	fmt.Printf("profile: %s\n", profile)
	fmt.Printf("<<<\n")
	metadata, err := c.DiscoverMetadata(profile)
	if err != nil {
		fmt.Printf("ERROR: Authenticate(): DiscoverMetadata() failed: %s\n", err)
		return nil, "", err
	}

	o := &oauth2.Config{
		ClientID:    c.ClientID,
		RedirectURL: c.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  metadata.AuthorizationEndpoint,
			TokenURL: metadata.TokenEndpoint,
		},
	}

	state, err := newState()
	if err != nil {
		fmt.Printf("ERROR: Authenticate(): newState() failed: %s\n", err)
		return nil, "", err
	}
	cv, err := newVerifier()
	if err != nil {
		fmt.Printf("ERROR: Authenticate(): newVerifier() failed: %s\n", err)
		return nil, "", err
	}

	authURL := o.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("scope", scope),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("code_challenge", s256Challenge(cv)),
		oauth2.SetAuthURLParam("me", profile),
	)

	return &AuthInfo{
		Metadata:     *metadata,
		Me:           profile,
		State:        state,
		CodeVerifier: cv,
	}, authURL, nil
}

// newState generates a new state value.
func newState() (string, error) {
	// OAuth 2.0 requires state to be printable ASCII, so base64 fits.
	// See https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.5.
	b := make([]byte, 64)
	_, err := cryptorand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateCallback validates the callback request by checking if the code exists
// and if the state is valid according to the provided AuthInfo.
func (c *Client) ValidateCallback(i *AuthInfo, r *http.Request) (string, error) {
	fmt.Printf("ValidateCallback():\n")
	fmt.Printf("\tAuthInfo: %#v\n", i)

	code := r.URL.Query().Get("code")
	if code == "" {
		return "", ErrCodeNotFound
	}

	state := r.URL.Query().Get("state")
	if state == "" {
		return "", ErrStateNotFound
	}

	if state != i.State {
		return "", ErrInvalidState
	}

	// If the issuer is not defined on the metadata, it means that the server does
	// not comply with the newer revision of IndieAuth. In that case, both the metadata
	// issuer and the "iss" should be empty. This should be backwards compatible.
	issuer := r.URL.Query().Get("iss")
	if issuer != i.Issuer {
		return "", ErrInvalidIssuer
	}

	fmt.Printf("ValidateCallback(): code: %#v\n", code)
	fmt.Printf("ValidateCallback(): state: %#v\n", state)
	fmt.Printf("ValidateCallback(): issuer: %#v\n", issuer)

	return code, nil
}

// ProfileFromToken retrieves the extra information from the token and
// creates a profile based on it. Note that the profile may be nil in case
// no information can be retrieved.
func ProfileFromToken(token *oauth2.Token) *Profile {
	fmt.Printf("ProfileFromToken():\n")
	me, ok := token.Extra("me").(string)
	if !ok || me == "" {
		return nil
	}

	p := &Profile{
		Me: me,
	}

	profile, ok := token.Extra("profile").(map[string]interface{})
	if !ok {
		return p
	}

	if name, ok := profile["name"].(string); ok {
		p.Profile.Name = name
	}

	if url, ok := profile["url"].(string); ok {
		p.Profile.URL = url
	}

	if photo, ok := profile["photo"].(string); ok {
		p.Profile.Photo = photo
	}

	if email, ok := profile["email"].(string); ok {
		p.Profile.Email = email
	}

	if webid, ok := profile["webid"].(string); ok {
		p.Profile.WebID = webid
	}

	return p
}

// GetToken exchanges the code for an oauth2.Token based on the provided information.
// It returns the token and an oauth2.Config object which can be used to create an http
// client that uses the token on future requests.
//
// Note that token.Raw may contain other information returned by the server, such as
// "Me", "Profile" and "Scope".
//
//	token, oauth2, err := client.GetToken(authData, code)
//	if err != nil {
//		// Do something
//	}
//	httpClient := oauth2.Client(context.Background(), token)
//
// You can now use httpClient to make requests to, for example, a Micropub endpoint. They
// are authenticated with token. See https://pkg.go.dev/golang.org/x/oauth2 for more details.
func (c *Client) GetToken(i *AuthInfo, code string) (*oauth2.Token, *oauth2.Config, error) {
	fmt.Printf("GetToken()\n")
	if i.TokenEndpoint == "" {
		return nil, nil, ErrNoEndpointFound
	}

	o := c.GetOAuth2(&i.Metadata)

	tok, err := o.Exchange(
		context.WithValue(context.Background(), oauth2.HTTPClient, c.Client),
		code,
		oauth2.SetAuthURLParam("client_id", c.ClientID),
		oauth2.SetAuthURLParam("code_verifier", i.CodeVerifier),
	)
	if err != nil {
		pc, file, line, _ := runtime.Caller(0)
		fmt.Printf("ERROR: %s[%s:%d] %v\n", runtime.FuncForPC(pc).Name(), file, line, err)
		return nil, nil, err
	}
	return tok, o, nil
}

// GetOAuth2 returns an oauth2.Config based on the given endpoints. This can be used
// to get an http.Client See https://pkg.go.dev/golang.org/x/oauth2 for more details.
func (c *Client) GetOAuth2(m *common.Metadata) *oauth2.Config {
	return &oauth2.Config{
		ClientID:    c.ClientID,
		RedirectURL: c.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  m.AuthorizationEndpoint,
			TokenURL: m.TokenEndpoint,
		},
	}
}

// FetchProfile fetches the user profile, exchanging the authentication code from
// their authentication endpoint, as described in the link below. Please note that
// this action consumes the code.
//
// https://indieauth.spec.indieweb.org/#profile-url-response
func (c *Client) FetchProfile(i *AuthInfo, code string) (*Profile, error) {
	fmt.Printf("FetchProfile():\n")
	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {c.RedirectURL},
		"client_id":     {c.ClientID},
		"code_verifier": {i.CodeVerifier},
	}

	r, err := http.NewRequest("POST", i.AuthorizationEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		fmt.Printf("ERROR: FetchProfile(): NewRequest() failed: %s\n", err)
		return nil, err
	}
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(v.Encode())))
	r.Header.Add("Accept", "application/json")

	res, err := c.Client.Do(r)
	if err != nil {
		fmt.Printf("ERROR: FetchProfile(): Do() failed: %s\n", err)
		return nil, err
	}
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Printf("ERROR: FetchProfile(): ReadAll() failed: %s\n", err)
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ERROR: FetchProfile(): %v\nResponse: %s", res.Status, data)
	}

	var profile *Profile
	err = json.Unmarshal(data, &profile)
	if err != nil {
		fmt.Printf("ERROR: FetchProfile(): Unmarshal() failed: %s\n", err)
		return nil, err
	}

	return profile, nil
}

// Checks if the server response to the authorization request is reporting an error.
func AuthReqServerError(req *http.Request) error {
	// See https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1
	// 4.1.2.1 Authorization Response - Error Response

	// If the server has accepted the redirect URI supplied by the IndieAuth
	// client, the callback (CallbackHandler) will have been called and any
	// error details will be in the response query string.
	//
	// If the server has rejected the supplied redirect URI, or the redirect
	// URI was missing, the server response will have been returned to the
	// authorization request origin, i.e. direct to the browser. The error
	// details will be in a JSON response body which the browser should
	// display directly.

	// Look for error (required) and error_description (optional)
	// in the response query string.

	err_code := req.URL.Query().Get("error")
	if err_code != "" {
		err_msg := err_code
		err_desc := req.URL.Query().Get("error_description")
		if err_desc != "" {
			err_msg += fmt.Sprintf(" [%s]", err_desc)
		}
		err := errors.New(err_msg)
		return err
	}

	return nil
}
