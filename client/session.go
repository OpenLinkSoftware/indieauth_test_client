package client

import (
	"errors"
	"net/http"
)

func session(w http.ResponseWriter, r *http.Request) (sessionId string, err error) {
	var cookie *http.Cookie
	cookie, err = r.Cookie("indie_auth_client_cookie")
	if err == nil {
		sessionId = cookie.Value
		if !sessionCheck(sessionId) {
			err = errors.New("Invalid session")
			sessionId = ""
		}
	}
	return
}

func sessionCheck(sessionId string) bool {
	// FIX ME when gClient is replaced.
	validSession := false
	if len(gClient.SessionID) > 0 && sessionId == gClient.SessionID {
		validSession = true
	}
	return validSession
}
