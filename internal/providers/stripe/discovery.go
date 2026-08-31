package stripe

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"os"  //reading env vars, finding the home directory
	"path/filepath"  //building file paths correctly across operating systems
	"strings"  //string manipulation (prefix checks, splitting, trimming)

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"
	
)

//Stripe's credential taxonomy, confirmed against docs.stripe.com and real-world
//usage: five distinct credential types, each identifiable by its prefix.
//Classification happens here, at discovery time, since the prefix alone is
//sufficient. No API call needed
const (

	//sk_ - full account access
	subtypeSecretKey models.CredentialSubtype = "secret_key"
	
	//rk_ - scoped permissions, chosen at creation
	subtypeRestrictedKey models.CredentialSubtype = "restricted_key"
	
	//pk_ - not a secret, safe client-side
	subtypePublishableKey models.CredentialSubtype = "publishable_key"
	
	//sk_org_ - spans multiple Stripe accounts
	subtypeOrganizationKey models.CredentialSubtype = "organization_key"
	
	//whsec_ - HMAC signing key, not an API credential
	subtypeWebhookSecret models.CredentialSubtype = "webhook_secret"
	
	//ca_ - public identifier for a Connect OAuth app, not a secret
	subtypeConnectClientID models.CredentialSubtype = "connect_client_id"

)

//classifyStripeCredential determines a credential's subtype from its prefix.
//sk_org_ is checked before sk_, since it's a more specific prefix that would
//otherwise match sk_'s check first
func classifyStripeCredential(value string) (models.CredentialSubtype, bool) {

	switch {

	case strings.HasPrefix(value, "sk_org_"):
		return subtypeOrganizationKey, true
	case strings.HasPrefix(value, "sk_"):
		return subtypeSecretKey, true
	case strings.HasPrefix(value, "rk_"):
		return subtypeRestrictedKey, true
	case strings.HasPrefix(value, "pk_"):
		return subtypePublishableKey, true
	case strings.HasPrefix(value, "whsec_"):
		return subtypeWebhookSecret, true
	case strings.HasPrefix(value, "ca_"):
		return subtypeConnectClientID, true
	default:
		return "", false

	}

}

//isLiveMode reports whether value is a live-mode credential, per Stripe's
//documented _live_/_test_ mode substring convention. Not meaningful for webhook
//secrets or Connect client IDs, which don't carry a mode in their value the
//same way
func isLiveMode(value string) bool {

	return strings.Contains(value, "_live_")

}

//Metadata keys this provider writes onto Credential.Metadata
//
//The raw credential value is NEVER written here. Metadata lives on Credential,
//which is embedded in CredentialAssessment, which is what gets written to local
//SQLite and used as the basis for cloud sync. Only non-sensitive pointers back
//to where the value lives are stored. secret.go re-fetches the actual value
//fresh, from its original source, every time Validate/GetActivity/RiskModifiers
//need it
const (

  	//"env" or "config_toml"
	metaSourceMethod = "stripe_source_method"

    //which env var, when metaSourceMethod is "env"
	metaSourceEnvVar = "stripe_source_env_var"

    //config.toml path, when metaSourceMethod is "config_toml"
	metaSourceFilePath = "stripe_source_file_path"

    //config.toml [section], when metaSourceMethod is "config_toml"
	metaSourceSection = "stripe_source_section"

    //config.toml key within the section, when metaSourceMethod is "config_toml"
	metaSourceKey = "stripe_source_key"

)

//Discover finds Stripe credentials via two independent methods:
//  1. Environment variables - DiscoveryPatternMatched. Checks the documented
//     STRIPE_API_KEY (takes precedence in the Stripe CLI over all other
//     sources) plus commonly-used conventional names seen across real
//     integrations: STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY,
//     STRIPE_WEBHOOK_SECRET, STRIPE_CONNECT_CLIENT_ID
//  2. ~/.config/stripe/config.toml, read directly - DiscoveryExact. The Stripe
//     CLI's own config file, confirmed real. Structured as [default] plus named
//     [project] sections (set via --project-name), each holding fields like
//     test_mode_api_key, live_mode_publishable_key, and secret_key. Every
//     project section is scanned
//A missing file/env var is not an error. Most machines will only have some of
//these configured. A file that exists but fails to read is a real error
//
//Both methods below call into secret.go's fetchFromX function to actually
//retrieve the value for presence-checking, but only ever store SOURCE
//information on the returned Credential; never the value itself. See the doc
//comment on the const block above
func (p *Provider) Discover(ctx context.Context, 
	cfg providers.DiscoveryConfig) ([]models.Credential, error) {

	var found []models.Credential

	found = append(found, discoverFromEnv()...)

	configPaths := cfg.Paths
	if len(configPaths) == 0 {

		if home, err := os.UserHomeDir(); err == nil {

			configPaths = []string{filepath.Join(home, ".config", "stripe", "config.toml")}

		}

	}
	for _, path := range configPaths {

		fromToml, err := discoverFromConfigToml(path)
		if err != nil {

			return nil, err

		}
		found = append(found, fromToml...)

	}

	return found, nil

}

//Known conventional env var names, checked explicitly. STRIPE_API_KEY is listed
//first since it is documented to take precedence over all other configuration
//sources when the Stripe CLI itself resolves credentials
var knownEnvVars = []string{

	"STRIPE_API_KEY",
	"STRIPE_SECRET_KEY",
	"STRIPE_PUBLISHABLE_KEY",
	"STRIPE_WEBHOOK_SECRET",
	"STRIPE_CONNECT_CLIENT_ID",

}

func discoverFromEnv() []models.Credential {

	var found []models.Credential

	//avoid double-counting if two env vars hold the same value
	seenEnvVars := make(map[string]bool)

	for _, envVar := range knownEnvVars {

		value, ok := fetchFromEnv(envVar)
		if !ok || value == "" {

			continue

		}
		subtype, ok := classifyStripeCredential(value)
		if !ok {

  			//present but doesn't match any known Stripe prefix
			continue

		}
		if seenEnvVars[value] {

			continue

		}
		seenEnvVars[value] = true
		found = append(found, models.Credential{

			Provider: "stripe",
			Subtype: subtype,
			Location: "env:" + envVar,
			DiscoveryConfidence: models.DiscoveryPatternMatched,
			Metadata: map[string]string{

				metaSourceMethod: "env",
				metaSourceEnvVar: envVar,

			},

		})

	}

	return found

}

//discoverFromConfigToml does a minimal, targeted read of the Stripe CLI's
//config.toml, looking for lines matching "key = value" under any [section]
//header, via secret.go's fetchFromConfigToml. Deliberately not a full TOML
//parser, mirroring the same reasoning as GitHub's hosts.yml handling: this
//file's structure for our purposes is simple and stable (flat key-value pairs
//per section), and a full TOML dependency is unwarranted for extracting a
//handful of predictable fields. Every value across every section that matches
//a known Stripe prefix is captured, regardless of the field name it's under.
//This means it also naturally tolerates Stripe adding new field names to this
//file later, since classification is by value shape, not by field name
func discoverFromConfigToml(path string) ([]models.Credential, error) {

	entries, err := scanConfigToml(path)
	if err != nil {

		return nil, err

	}

	var found []models.Credential
	for _, entry := range entries {

		subtype, ok := classifyStripeCredential(entry.value)
		if !ok {

			continue

		}

		found = append(found, models.Credential{

			Provider: "stripe",
			Subtype: subtype,
			Location: fmt.Sprintf("%s [%s project, %s]", path, entry.section, entry.key),
			DiscoveryConfidence: models.DiscoveryExact,
			Metadata: map[string]string{

				metaSourceMethod: "config_toml",
				metaSourceFilePath: path,
				metaSourceSection: entry.section,
				metaSourceKey: entry.key,

			},

		})

	}

	return found, nil

}