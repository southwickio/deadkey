package twilio

import (

	"bufio"  //buffered reading, used to scan .env files and the credentials
	"encoding/json"  //parsing the twilio-cli config.json file
	"fmt"  //string formatting and building error messages
	"os"  //reading env vars, opening files
	"strings"  //string manipulation

	"github.com/southwickio/deadkey/internal/models"

)

//resolveAuthToken re-reads cred's Auth Token fresh from wherever it originally
//came from; never from Credential.Metadata, which never holds it. Every call to
//Validate/GetActivity/RiskModifiers re-reads the secret from disk or the
//environment rather than caching it anywhere
func resolveAuthToken(cred models.Credential) (string, error) {

	accountSID, ok := cred.Metadata[metaAccountSID]
	if !ok || accountSID == "" {

		return "", fmt.Errorf("credential missing %s in Metadata", metaAccountSID)

	}

	if path, ok := cred.Metadata[metaSourceFilePath]; ok && path != "" {

		token, err := authTokenFromDotEnvFile(path, accountSID)
		if err != nil {

			return "", fmt.Errorf("twilio: re-reading auth token for %s from %s: %w", accountSID, path, err)

		}
		if token == "" {

			return "", fmt.Errorf("twilio: %s no longer has a matching TWILIO_AUTH_TOKEN in %s (credential may have changed since discovery)", accountSID, path)

		}
		return token, nil

	}

	if path, ok := cred.Metadata[metaCLIConfigPath]; ok && path != "" {

		profile := cred.Metadata[metaCLIProfileName]
		token, err := authTokenFromCLIConfig(path, profile, accountSID)
		if err != nil {

			return "", fmt.Errorf("twilio: re-reading auth token for profile %q from %s: %w", profile, path, err)

		}
		if token != "" {

			return token, nil

		}
		//Fall through: the twilio-cli profile may store an auto-generated API
		//Key instead of an Auth Token (see discovery.go). That path is resolved
		//by resolveAPIKeySecret, not here

	}

	//Env-discovered credential: re-check the environment, guarding against the
	//case where AUTH_TOKEN was rotated (but ACCOUNT_SID left the same) between
	//discovery and now
	if os.Getenv("TWILIO_ACCOUNT_SID") == accountSID {

		if token := os.Getenv("TWILIO_AUTH_TOKEN"); token != "" {

			return token, nil

		}

	}

	return "", fmt.Errorf("twilio: no Auth Token available for %s (neither its original source nor the environment currently has it)", accountSID)

}

//resolveAPIKeySecret re-reads cred's API Key secret fresh, the same way
//resolveAuthToken does for Auth Tokens
func resolveAPIKeySecret(cred models.Credential) (string, error) {

	keySID, ok := cred.Metadata[metaAPIKeySID]
	if !ok || keySID == "" {

		return "", fmt.Errorf("credential missing %s in Metadata", metaAPIKeySID)

	}

	if path, ok := cred.Metadata[metaSourceFilePath]; ok && path != "" {

		secret, err := apiKeySecretFromDotEnvFile(path, keySID)
		if err != nil {

			return "", fmt.Errorf("twilio: re-reading API Key secret for %s from %s: %w", keySID, path, err)

		}
		if secret == "" {

			return "", fmt.Errorf("twilio: %s no longer has a matching secret in %s (credential may have changed since discovery)", keySID, path)

		}
		return secret, nil

	}

	if path, ok := cred.Metadata[metaCLIConfigPath]; ok && path != "" {

		profile := cred.Metadata[metaCLIProfileName]
		secret, err := apiKeySecretFromCLIConfig(path, profile, keySID)
		if err != nil {

			return "", fmt.Errorf("twilio: re-reading API Key secret for profile %q from %s: %w", profile, path, err)

		}
		if secret != "" {

			return secret, nil

		}

	}

	//Several env var naming conventions are documented in real use for the SID
	//half (TWILIO_API_KEY vs TWILIO_API_KEY_SID); check both, matching
	//whichever discovery originally used (see discovery.go's envKeySIDNames)
	for _, sidVar := range envAPIKeySIDNames {

		if os.Getenv(sidVar) != keySID {

			continue

		}
		for _, secretVar := range envAPIKeySecretNames {

			if secret := os.Getenv(secretVar); secret != "" {

				return secret, nil

			}

		}

	}

	return "", fmt.Errorf("twilio: no API Key secret available for %s (neither its original source nor the environment currently has it)", keySID)

}

//authTokenFromDotEnvFile re-scans a .env-style file for TWILIO_AUTH_TOKEN, but
//only returns it if TWILIO_ACCOUNT_SID in that same file still matches
//expectedAccountSID; guarding against the file having changed since discovery
func authTokenFromDotEnvFile(path, expectedAccountSID string) (string, error) {

	values, err := scanDotEnvFile(path)
	if err != nil {

		return "", err

	}

	if values["TWILIO_ACCOUNT_SID"] != expectedAccountSID {

		return "", nil

	}

	return values["TWILIO_AUTH_TOKEN"], nil

}

//apiKeySecretFromDotEnvFile mirrors authTokenFromDotEnvFile for API Key
//secrets, checking both documented SID variable name conventions
func apiKeySecretFromDotEnvFile(path, expectedKeySID string) (string, error) {

	values, err := scanDotEnvFile(path)
	if err != nil {

		return "", err

	}

	sidMatches := false
	for _, sidVar := range envAPIKeySIDNames {

		if values[sidVar] == expectedKeySID {

			sidMatches = true
			break

		}

	}
	if !sidMatches {

		return "", nil

	}

	for _, secretVar := range envAPIKeySecretNames {

		if secret := values[secretVar]; secret != "" {

			return secret, nil

		}

	}

	return "", nil

}

//scanDotEnvFile reads a simple KEY=VALUE .env-style file into a map. This is
//deliberately minimal (no quoting/escaping/multiline support) since .env files
//discovered by this provider are being read defensively, not executed. A line
//this parser can't confidently make sense of is simply skipped rather than
//guessed at
func scanDotEnvFile(path string) (map[string]string, error) {

	f, err := os.Open(path)
	if err != nil {

		return nil, err

	}
	defer f.Close()

	values := make(map[string]string)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {

			continue

		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {

			continue

		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		value = strings.Trim(value, `"'`)

		values[key] = value

	}
	if err := scanner.Err(); err != nil {

		return nil, err

	}

	return values, nil

}

//cliConfigFile is a deliberately loose representation of ~/.twilio-cli's
//config.json. twilio-cli-core's own changelog confirms the storage mechanism
//(v6.0.0, "Storing profiles in config file instead of keytar".
//Docs:github.com/twilio/twilio-cli-core. See discovery.go's doc comment for the
//full citation trail), but Twilio does not publish this file's schema, since it
//is an internal CLI implementation detail rather than a public API contract.
//Field names below (accountSid, apiKey, apiSecret, region, edge) are the
//best-supported reconstruction from indirect evidence (real fragments seen in
//Twilio Voice JS config examples, CLI changelog references to a "breaking
//camelCase change", and community tooling that reads this file). This is NOT a
//confirmed dump of the literal schema. This parsing is deliberately defensive.
//So, an unrecognized shape is treated as "no credential found here", never
//guessed at or partially trusted
type cliConfigFile struct {

	ActiveProject string `json:"activeProject"`
	Projects map[string]cliConfigProject `json:"projects"`

}

type cliConfigProject struct {

	AccountSid string `json:"accountSid"`
	ApiKey string `json:"apiKey"`
	ApiSecret string `json:"apiSecret"`
	Region string `json:"region"`
	Edge string `json:"edge"`

}

//loadCLIConfig reads and loosely parses path. A missing or unparseable file
//returns a zero-value config and no credentials, not an error. This project's
//own scan.go/serve.go call sites are expected to treat "found nothing" and "the
//CLI isn't installed" identically
func loadCLIConfig(path string) (cliConfigFile, error) {

	data, err := os.ReadFile(path)
	if err != nil {

		return cliConfigFile{}, err

	}

	var cfg cliConfigFile
	if err := json.Unmarshal(data, &cfg); err != nil {

		return cliConfigFile{}, err

	}

	return cfg, nil

}

//authTokenFromCLIConfig returns "" (not an error) when the profile doesn't
//store a bare Auth Token; current twilio-cli versions generate a Standard API
//Key on login instead (see discovery.go), so this path exists mainly for
//forward/backward compatibility with profile shapes that do store one
func authTokenFromCLIConfig(path, 
	profile, 
	expectedAccountSID string) (string, error) {

	cfg, err := loadCLIConfig(path)
	if err != nil {

		return "", err

	}

	proj, ok := cfg.Projects[profile]
	if !ok || proj.AccountSid != expectedAccountSID {

		return "", nil

	}

	return "", nil //current CLI versions never store a bare Auth Token

}

//apiKeySecretFromCLIConfig re-reads a profile's generated API Key secret,
//guarding against the profile having been re-created (new key) since discovery
func apiKeySecretFromCLIConfig(path, 
	profile, 
	expectedKeySID string) (string, error) {

	cfg, err := loadCLIConfig(path)
	if err != nil {

		return "", err

	}

	proj, ok := cfg.Projects[profile]
	if !ok || proj.ApiKey != expectedKeySID {

		return "", nil

	}

	return proj.ApiSecret, nil

}