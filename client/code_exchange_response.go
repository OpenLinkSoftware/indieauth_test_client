package client

import (
	"golang.org/x/oauth2"
)

// Holds the fields of the response from redeeming the authorization code.
// Either the token endpoint response, or the authorization endpoint response.
type CodeExchangeResponse struct {
	AccessToken  string
	ExpiresIn    float64
	RefreshToken string
	TokenType    string
	Profile
}

func (cer *CodeExchangeResponse) GetTokenContents(t *oauth2.Token) {
	cer.AccessToken = t.Extra("access_token").(string)
	cer.ExpiresIn = t.Extra("expires_in").(float64)
	cer.RefreshToken = t.Extra("refresh_token").(string)
	cer.TokenType = t.Extra("token_type").(string)
	cer.Profile.Me = t.Extra("me").(string)

	profile := t.Extra("profile").(map[string]interface{})
	cer.Profile.Profile.URL = profile["url"].(string)

	name := profile["name"]
	if name != nil {
		cer.Profile.Profile.Name = name.(string)
	}

	email := profile["email"]
	if email != nil {
		cer.Profile.Profile.Email = email.(string)
	}

	webid := profile["webid"]
	if webid != nil {
		cer.Profile.Profile.WebID = webid.(string)
	}

	photo := profile["photo"]
	if photo != nil {
		cer.Profile.Profile.Photo = photo.(string)
	}
}
