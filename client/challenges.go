package client

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// newVerifier generates a new code_verifier value.
func newVerifier() (string, error) {
	// A valid code_verifier has a minimum length of 43 characters and a maximum
	// length of 128 characters per https://datatracker.ietf.org/doc/html/rfc7636#section-4.1.
	// Use 64 bytes of random data, which becomes 86 bytes after base64 encoding.
	b := make([]byte, 64)
	_, err := cryptorand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// s256Challenge computes the code_challenge corresponding to the
// specified code_verifier using the S256 code challenge method:
//
//	S256
//		code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
//
// Use base64 URL encoding without padding as required by RFC 7636.
//
// See https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
// and https://datatracker.ietf.org/doc/html/rfc7636#section-3.
func s256Challenge(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func containsString(s []string, v string) bool {
	for _, vv := range s {
		if vv == v {
			return true
		}
	}
	return false
}
