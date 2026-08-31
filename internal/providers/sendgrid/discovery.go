package sendgrid

import (

	"context"  // carries cancellation/deadline signals through function calls
	"strings"  // string manipulation (prefix checks)

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

const (

	subtypeAPIKey models.CredentialSubtype = "api_key"
	subtypeLegacyCredentials models.CredentialSubtype = "legacy_username_password"

)

//Metadata keys this provider writes onto Credential.Metadata
//
//The raw credential value is NEVER written here. Metadata lives on Credential,
//which is embedded in CredentialAssessment, which is what gets written to local
//SQLite and used as the basis for cloud sync. Only non-sensitive pointers back
//to where the value lives are stored. secret.go re-fetches the actual value
//fresh, from its original source, every time Validate/GetActivity/RiskModifiers
//need it
const (

 	//for subtypeAPIKey: which env var
	metaSourceEnvVar = "sendgrid_source_env_var"

    //for subtypeLegacyCredentials: which env var holds the username
	metaUsernameEnvVar = "sendgrid_username_env_var"

    //for subtypeLegacyCredentials: which env var holds the password
	metaPasswordEnvVar = "sendgrid_password_env_var"

    //comma-separated, populated by Validate, read by RiskModifiers. Not
	//sensitive, a classification label, not the credential itself
	metaScopes   = "sendgrid_scopes"   

)

//Discover finds SendGrid credentials via environment variables.
//DiscoveryPatternMatched in all cases. Unlike AWS's structured credentials file
//or Stripe's config.toml, no official SendGrid CLI config file exists to read
//structurally (confirmed against the real sendgrid/sendgrid-cli source: it uses
//only env vars / .env, with no dedicated config file of its own)
//
//API keys: SENDGRID_API_KEY (the standard convention used by every official
//SendGrid SDK, confirmed in SendGrid's own documentation) and SENDGRID_TOKEN
//(confirmed real, required for certain admin commands in the official
//sendgrid-cli). Classified by the "SG." prefix, NOT by exact character length,
//since real-world reports disagree on whether keys are 69 or 70 characters;
//prefix alone is currently the reliable signal
//
//Legacy username/password: SendGrid still accepts HTTP Basic Auth with a parent
//account's username/password for a narrow set of operations (specifically,
//updating an API key's scopes) and this predates API keys entirely. There is no
//confirmed universal env var naming convention for this pair the way there is
//for the API key - SENDGRID_USERNAME/SENDGRID_PASSWORD are checked as a
//reasonable, but not independently confirmed, convention. Flagged here rather
//than silently omitted, since SendGrid's own hardening guidance explicitly
//warns about "every teammate who logs in with a SendGrid password rather than
//through your IdP" as a live risk worth auditing for
//
//Both branches below only ever store WHICH env var a value came from, never the
//value itself. secret.go's resolveSendGridAPIKey and
//resolveSendGridLegacyCredentials re-read the actual env vars fresh whenever
//Validate/GetActivity/RiskModifiers need them
func (p *Provider) Discover(ctx context.Context, 
	cfg providers.DiscoveryConfig) ([]models.Credential, error) {

	var found []models.Credential

	for _, envVar := range []string{"SENDGRID_API_KEY", "SENDGRID_TOKEN"} {

		value, ok := fetchFromEnv(envVar)
		if !ok || value == "" {

			continue

		}
		if !strings.HasPrefix(value, "SG.") {

			continue

		}
		found = append(found, models.Credential{

			Provider: "sendgrid",
			Subtype: subtypeAPIKey,
			Location: "env:" + envVar,
			DiscoveryConfidence: models.DiscoveryPatternMatched,
			Metadata: map[string]string{metaSourceEnvVar: envVar},

		})

	}

	usernameEnvVar := "SENDGRID_USERNAME"
	passwordEnvVar := "SENDGRID_PASSWORD"
	username, usernameOK := fetchFromEnv(usernameEnvVar)
	password, passwordOK := fetchFromEnv(passwordEnvVar)
	if usernameOK && passwordOK && username != "" && password != "" {

		found = append(found, models.Credential{

			Provider: "sendgrid",
			Subtype: subtypeLegacyCredentials,
			Location: "env:SENDGRID_USERNAME / env:SENDGRID_PASSWORD",
			DiscoveryConfidence: models.DiscoveryPatternMatched,
			Metadata: map[string]string{

				metaUsernameEnvVar: usernameEnvVar,
				metaPasswordEnvVar: passwordEnvVar,

			},

		})

	}

	return found, nil

}