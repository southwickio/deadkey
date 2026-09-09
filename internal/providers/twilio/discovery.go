package twilio

import (

	"context"  //carries cancellation/deadline signals through function calls
	"os"  //reading env vars, finding the home directory
	"path/filepath"  //building file paths correctly across operating systems
	"regexp"  //pattern-matching credential shapes inside free-form files

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//Twilio's credential taxonomy, confirmed against docs.twilio.com. There are two
//fundamentally different shapes a Twilio credential can take:
//  - An Account SID (AC...) + Auth Token pair: equivalent to full account
//    access. Docs: twilio.com/docs/iam/api/account
//  - An API Key (SK...) + Secret pair, of type Main, Standard, or Restricted.
//    Docs: twilio.com/docs/iam/api-keys. Key TYPE is not exposed by the Key
//    resource's own fetch response (confirmed against two independently
//    generated SDKs. See risk_modifiers.go) so it cannot be classified at
//    discovery time; that inference happens later, in RiskModifiers
const (

	subtypeAuthToken models.CredentialSubtype = "auth_token"
	subtypeAPIKey    models.CredentialSubtype = "api_key"

)

//This file defines named constants for the Metadata keys this provider uses
//(metaAccountSID, metaAPIKeySID, etc), rather than typing raw string literals
//like "twilio_account_sid" directly wherever they're needed in the code.
//Declared here as constants, per credential.go's guidance
//
//The Auth Token and the API Key secret are deliberately never written to
//Metadata, per this project's cornerstone rule that secret values must never be
//stored there (see credential.go). Both are re-read fresh from their original
//source only when Validate/GetActivity/RiskModifiers actually need them
const (

	//The Account SID half of an Auth-Token credential, or the account this
	//API Key belongs to (when known - see metaAccountSIDUnknown below)
	metaAccountSID = "twilio_account_sid"

	//The Key resource's own SID (SK...) for an API-Key credential
	metaAPIKeySID = "twilio_api_key_sid"

	//Which env var name matched, when discovered via environment variables.
	//Twilio's own ecosystem is inconsistent about which env var name holds the
	//API Key SID (TWILIO_API_KEY vs TWILIO_API_KEY_SID both appear in official
	//Twilio documentation and tooling). It's recorded so
	//RiskModifiers/telemetry can note which convention was in use, without
	//needing to re-derive it
	metaEnvVarName = "twilio_env_var"

	//Which file this credential came from (.env-style pattern match). Needed to
	//re-read the secret later, never the secret itself
	metaSourceFilePath = "twilio_source_file"

	//twilio-cli config.json path and profile name (structured discovery).
	//Needed to re-read the secret later, never the secret itself
	metaCLIConfigPath   = "twilio_cli_config_path"
	metaCLIProfileName  = "twilio_cli_profile"

	//Twilio Region/Edge captured alongside the credential, if set. Needed by
	//Validate to target the correct regional hostname. See validate.go.
	//Docs: twilio.com/docs/global-infrastructure/understanding-twilio-regions
	metaRegion = "twilio_region"
	metaEdge   = "twilio_edge"

	//Set to "true" when an API Key was found with no Account SID anywhere
	//nearby. Twilio's API has no way to identify which account an API Key
	//belongs to from the key alone. Every request path requires
	///Accounts/{AccountSid}/... regardless of which credential authenticates it
	//(confirmed across twilio-node, twilio-go, twilio-elixir issue history;
	//there is no "resolve my account from just this key" endpoint anywhere in
	//Twilio's documented API). Rather than silently dropping an orphaned key or
	//guessing at its account, it is still reported as a found credential.
	//Validate returns ValidationError explaining exactly why it can't be
	//checked, so the person sees it and can pair it manually
	metaAccountSIDUnknown = "twilio_account_sid_unknown"

)

//Both documented naming conventions for an API Key's SID and secret appear in
//real, current Twilio documentation and tooling: the CLI/general docs use
//TWILIO_API_KEY / TWILIO_API_SECRET, while several official quickstarts and
//GitHub Actions integrations use TWILIO_API_KEY_SID / TWILIO_API_KEY_SECRET.
//Both are checked, since neither is more "correct" than the other in practice
var envAPIKeySIDNames = []string{"TWILIO_API_KEY", "TWILIO_API_KEY_SID"}
var envAPIKeySecretNames = []string{"TWILIO_API_SECRET", "TWILIO_API_KEY_SECRET"}

//Shape patterns for pattern-matched (.env-style file) discovery. Twilio SIDs
//are always exactly 34 characters: a 2-letter type prefix followed by 32 hex
//characters. Docs: twilio.com/docs/glossary/what-is-a-sid
var (

	accountSIDPattern = regexp.MustCompile(`\bAC[0-9a-fA-F]{32}\b`)
	apiKeySIDPattern  = regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)

)

//Discover finds Twilio credentials via three independent methods:
//  1. Environment variables (TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN, and both
//     documented API Key naming conventions). DiscoveryPatternMatched, same
//     classification AWS uses for its own env-var path: an env var carries no
//     structural guarantee its value is a credential at all
//  2. .env-style files, when cfg.Paths is non-empty and cfg.PatternMatching is
//     enabled. DiscoveryPatternMatched, scanning for Twilio's distinctive
//     AC.../SK... SID shapes
//  3. twilio-cli's config.json (default ~/.twilio-cli/config.json, or cfg.Paths
//     override). DiscoveryExact: this is deliberate, structured parsing of a
//     known (if not officially published) JSON shape, not a regex guess.
//     Current twilio-cli (v6.0.0+, released 2022-01-18 per twilio-cli-core's
//     own changelog: "Storing profiles in config file instead of keytar")
//     stores a profile's generated API Key SID and secret directly in this
//     file. Twilio-cli versions older than v6.0.0 instead store credentials via
//     the OS keychain (the "keytar" npm package) and are NOT supported by this
//     discovery path. Stated explicitly as a non-goal, not silently skipped
//
//A missing file, in either file-based method, is not an error: most machines
//simply won't have one. A file that exists but fails to parse/read for another
//reason (permissions, corruption) is likewise treated as "nothing found here"
//for config.json specifically, since its schema is not officially published and
//a defensive skip is safer than guessing (see secret.go's cliConfigFile doc
//comment)
func (p *Provider) Discover(ctx context.Context,
	cfg providers.DiscoveryConfig) ([]models.Credential, error) {

	var found []models.Credential

	region, edge := regionAndEdgeFromEnv()

	found = append(found, discoverFromEnv(region, edge)...)

	if cfg.PatternMatching {

		for _, path := range cfg.Paths {

			found = append(found, discoverFromDotEnvFile(path)...)

		}

	}

	cliPaths := cfg.Paths
	if len(cliPaths) == 0 {

		if home, err := os.UserHomeDir(); err == nil {

			cliPaths = []string{filepath.Join(home, ".twilio-cli", "config.json")}

		}

	}
	for _, path := range cliPaths {

		found = append(found, discoverFromCLIConfig(path)...)

	}

	return found, nil

}

//regionAndEdgeFromEnv reads TWILIO_REGION/TWILIO_EDGE, which take precedence
//over any profile-stored value per Twilio's own CLI documentation. Absence of
//either is not defaulted here to "us1"/"". That default is applied later, at
//Validate time, so DiscoveryEvidence accurately reflects what was actually
//found versus assumed
func regionAndEdgeFromEnv() (region, edge string) {

	return os.Getenv("TWILIO_REGION"), os.Getenv("TWILIO_EDGE")

}

//discoverFromEnv checks both credential shapes and both API Key naming
//conventions
func discoverFromEnv(region, edge string) []models.Credential {

	var found []models.Credential

	accountSID := os.Getenv("TWILIO_ACCOUNT_SID")

	if authToken := os.Getenv("TWILIO_AUTH_TOKEN"); accountSID != "" && authToken != "" {

		found = append(found, models.Credential{

			Provider:            "twilio",
			Subtype:             subtypeAuthToken,
			Location:            "env:TWILIO_ACCOUNT_SID+TWILIO_AUTH_TOKEN",
			DiscoveryConfidence: models.DiscoveryPatternMatched,
			Metadata:            withRegionEdge(map[string]string{

				metaAccountSID: accountSID,

			}, region, edge),

		})

	}

	for _, sidVar := range envAPIKeySIDNames {

		keySID := os.Getenv(sidVar)
		if keySID == "" {

			continue

		}

		var secret string
		for _, secretVar := range envAPIKeySecretNames {

			if s := os.Getenv(secretVar); s != "" {

				secret = s
				break

			}

		}
		if secret == "" {

			continue

		}

		meta := map[string]string{

			metaAPIKeySID: keySID,
			metaEnvVarName: sidVar,

		}
		if accountSID != "" {

			meta[metaAccountSID] = accountSID

		} else {

			meta[metaAccountSIDUnknown] = "true"

		}

		found = append(found, models.Credential{

			Provider:            "twilio",
			Subtype:             subtypeAPIKey,
			Location:            "env:" + sidVar,
			DiscoveryConfidence: models.DiscoveryPatternMatched,
			Metadata:            withRegionEdge(meta, region, edge),

		})

		break //don't double-report the same key under both naming conventions

	}

	return found

}

//withRegionEdge copies meta and adds region/edge entries when non-empty
func withRegionEdge(meta map[string]string, region, edge string) map[string]string {

	if region != "" {

		meta[metaRegion] = region

	}
	if edge != "" {

		meta[metaEdge] = edge

	}
	return meta

}

//discoverFromDotEnvFile pattern-matches Twilio's distinctive SID shapes inside
//path, pairing an API Key with whatever Account SID (if any) also appears in
//the same file. The documented common real-world layout (confirmed against a
//published Twilio credential-scanning tool's own setup instructions, which
//pair TWILIO_ACCOUNT_SID + TWILIO_API_KEY_SID + TWILIO_API_KEY_SECRET in one
//file). A missing file is not an error; the caller (Discover) doesn't
//distinguish "file absent" from "nothing matched" for this method, since both
//mean the same thing to the rest of the pipeline
func discoverFromDotEnvFile(path string) []models.Credential {

	values, err := scanDotEnvFile(path)
	if err != nil {

		return nil

	}

	var found []models.Credential
	region := values["TWILIO_REGION"]
	edge := values["TWILIO_EDGE"]

	accountSID := values["TWILIO_ACCOUNT_SID"]
	if accountSID == "" {

		accountSID = firstMatch(accountSIDPattern, values)

	}

	if authToken := values["TWILIO_AUTH_TOKEN"]; accountSID != "" && authToken != "" {

		found = append(found, models.Credential{

			Provider:            "twilio",
			Subtype:             subtypeAuthToken,
			Location:            path + " [TWILIO_ACCOUNT_SID+TWILIO_AUTH_TOKEN]",
			DiscoveryConfidence: models.DiscoveryPatternMatched,
			Metadata: withRegionEdge(map[string]string{

				metaAccountSID:     accountSID,
				metaSourceFilePath: path,

			}, region, edge),

		})

	}

	for _, sidVar := range envAPIKeySIDNames {

		keySID := values[sidVar]
		if keySID == "" {

			continue

		}

		var secret string
		for _, secretVar := range envAPIKeySecretNames {

			if s := values[secretVar]; s != "" {

				secret = s
				break

			}

		}
		if secret == "" {

			continue

		}

		meta := map[string]string{

			metaAPIKeySID:      keySID,
			metaEnvVarName:     sidVar,
			metaSourceFilePath: path,

		}
		if accountSID != "" {

			meta[metaAccountSID] = accountSID

		} else {

			//Real gap: an API Key with no Account SID anywhere in the same
			//file. Reported, not dropped. See metaAccountSIDUnknown's doc
			//comment and validate.go's handling
			meta[metaAccountSIDUnknown] = "true"

		}

		found = append(found, models.Credential{

			Provider:            "twilio",
			Subtype:             subtypeAPIKey,
			Location:            path + " [" + sidVar + "]",
			DiscoveryConfidence: models.DiscoveryPatternMatched,
			Metadata:            withRegionEdge(meta, region, edge),

		})

		break

	}

	return found

}

//firstMatch scans a .env-style key/value map's raw values for pattern's first
//match, as a fallback when TWILIO_ACCOUNT_SID isn't the literal variable name
//used (some real-world files alias it, e.g. within a nested JSON blob pasted
//into a single .env line)
func firstMatch(pattern *regexp.Regexp, values map[string]string) string {

	for _, v := range values {

		if m := pattern.FindString(v); m != "" {

			return m

		}

	}
	return ""

}

//discoverFromCLIConfig reads every profile in twilio-cli's config.json. See
//Discover's doc comment for the v6.0.0/keytar cutoff this depends on
func discoverFromCLIConfig(path string) []models.Credential {

	cfg, err := loadCLIConfig(path)
	if err != nil {

		return nil

	}

	var found []models.Credential

	for name, proj := range cfg.Projects {

		if proj.AccountSid == "" || proj.ApiKey == "" || proj.ApiSecret == "" {

			continue

		}

		found = append(found, models.Credential{

			Provider:            "twilio",
			Subtype:             subtypeAPIKey,
			Location:            path + " [profile:" + name + "]",
			DiscoveryConfidence: models.DiscoveryExact,
			Metadata: withRegionEdge(map[string]string{

				metaAccountSID:     proj.AccountSid,
				metaAPIKeySID:      proj.ApiKey,
				metaCLIConfigPath:  path,
				metaCLIProfileName: name,

			}, proj.Region, proj.Edge),

		})

	}

	return found

}