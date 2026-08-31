package sendgrid

import (

	"fmt"  //string formatting and building error messages
	"os"   //reading environment variables

	"github.com/southwickio/deadkey/internal/models"

)

//This file owns every actual credential-value retrieval in the SendGrid
//provider. Values are re-read fresh from their env vars every time
//Validate/GetActivity/RiskModifiers need them. Never stored on
//Credential.Metadata, which only ever holds which env var to check (see
//discovery.go's const block)

func fetchFromEnv(envVar string) (string, bool) {

	value := os.Getenv(envVar)
	if value == "" {

		return "", false

	}
	return value, true
}

//resolveSendGridAPIKey re-fetches an API key credential's value fresh.
func resolveSendGridAPIKey(cred models.Credential) (string, error) {

	envVar, ok := cred.Metadata[metaSourceEnvVar]
	if !ok || envVar == "" {

		return "", 
		fmt.Errorf("credential missing %s in Metadata", metaSourceEnvVar)

	}
	value, ok := fetchFromEnv(envVar)
	if !ok {

		return "", fmt.Errorf("sendgrid: %s is no longer set", envVar)

	}
	return value, nil

}

//resolveSendGridLegacyCredentials re-fetches a legacy username/password
//credential's values fresh
func resolveSendGridLegacyCredentials(cred models.Credential) (username, password string, err error) {

	usernameEnvVar, ok := cred.Metadata[metaUsernameEnvVar]
	if !ok || usernameEnvVar == "" {

		return "", 
		"", 
		fmt.Errorf("credential missing %s in Metadata", metaUsernameEnvVar)

	}
	passwordEnvVar, ok := cred.Metadata[metaPasswordEnvVar]
	if !ok || passwordEnvVar == "" {

		return "", 
		"", 
		fmt.Errorf("credential missing %s in Metadata", metaPasswordEnvVar)

	}
	username, ok = fetchFromEnv(usernameEnvVar)
	if !ok {

		return "", 
		"", 
		fmt.Errorf("sendgrid: %s is no longer set", usernameEnvVar)

	}
	password, ok = fetchFromEnv(passwordEnvVar)
	if !ok {

		return "", 
		"", 
		fmt.Errorf("sendgrid: %s is no longer set", passwordEnvVar)

	}
	return username, password, nil

}