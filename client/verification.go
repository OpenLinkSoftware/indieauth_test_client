package client

import (
	"errors"
	"fmt"
	"net"
	urlpkg "net/url"
	"strings"
)

var (
	ErrInvalidScheme   error = errors.New("Profile URL: scheme must be either http or https")
	ErrEmptyHost       error = errors.New("Profile URL: host must not be empty")
	ErrEmptyPath       error = errors.New("Profile URL: path must not be empty")
	ErrInvalidPath     error = errors.New("Profile URL: path cannot contain single or double dots")
	ErrInvalidFragment error = errors.New("Profile URL: fragment must be empty")
	ErrUserIsSet       error = errors.New("Profile URL: user and or password must not be set")
	ErrPortIsSet       error = errors.New("Profile URL: port must not be set")
	ErrIsIP            error = errors.New("Profile URL: cannot be ip address")
	ErrIsNonLoopback   error = errors.New("client id cannot be non-loopback ip")
)

// IsValidProfileURL validates the profile URL according to the specification.
// https://indieauth.spec.indieweb.org/#user-profile-url
func IsValidProfileURL(profile string) error {
	url, err := urlpkg.Parse(profile)
	if err != nil {
		fmt.Printf("ERROR: IsValidProfileURL(): Parse() failed: %s\n", err)
		return err
	}
	fmt.Printf("IsValidProfileURL(): parsed profile URL: %#v\n", url)

	if url.Scheme != "http" && url.Scheme != "https" {
		return ErrInvalidScheme
	}

	if url.Host == "" {
		return ErrEmptyHost
	}

	if url.Path == "" {
		return ErrEmptyPath
	}

	if strings.Contains(url.Path, "./") || strings.Contains(url.Path, "../") {
		return ErrInvalidPath
	}

	if url.Fragment != "" {
		return ErrInvalidFragment
	}

	if url.User.String() != "" {
		return ErrUserIsSet
	}

	// FIX ME: Allow port to be set for development. Disable for production.
	/*
		if url.Port() != "" {
			return ErrPortIsSet
		}
	*/

	if net.ParseIP(url.Host) != nil {
		return ErrIsIP
	}

	return nil
}

// CanonicalizeURL checks if a URL has a path, and appends a path "/""
// if it has no path.
func CanonicalizeURL(urlStr string) string {
	// NOTE: parsing a URL without scheme will most likely put the host as path.
	// That's why the scheme is added first.
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	url, err := urlpkg.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	if url.Path == "" {
		url.Path = "/"
	}

	return url.String()
}
