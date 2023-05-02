package common

import (
	"log"
	"os"
	"path/filepath"
)

type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	// IntrospectionEndpoint                      string   `json:"introspection_endpoint"`
	// IntrospectionEndpointAuthMethodsSupported  []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpoint string `json:"revocation_endpoint"`
	// RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	// ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ServiceDocumentation                       string   `json:"service_documentation"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
	// UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
}

func IndieAuthRootDir() string {
	indieAuthRootDir, exists := os.LookupEnv("INDIEAUTH_ROOT")
	if !exists {
		currentDir, _ := os.Getwd()
		// FIX ME:
		// This hack only works for development when the cmd binaries
		// haven't been installed.
		//
		// Assume indieauth-client has been started from folder cmd/indieauth-client
		// and/or indieauth-server has been started from folder cmd/indieauth-server
		//
		// Instead of the hack, just fail if INDIEAUTH_ROOT hasn't been set.
		indieAuthRootDir = filepath.Clean(currentDir + "/../..")
		// TO DO: Use a logging framework which supports log levels. e.g. logrus.
		log.Printf("Warning: Environment variable INDIEAUTH_ROOT is not set.")
		log.Printf("Warning: Defaulting INDIEAUTH_ROOT to %s", indieAuthRootDir)
		os.Setenv("INDIEAUTH_ROOT", indieAuthRootDir)
	}
	return indieAuthRootDir
}
