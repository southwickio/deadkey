package stripe

import (

	"bufio"  //reads the config file line by line
	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"os"  //reading env vars, opening files
	"strings"  //string manipulation (prefix checks, splitting, trimming)

	"github.com/southwickio/deadkey/internal/models"

)

//This file owns every actual credential-value retrieval in the Stripe provider.
//discovery.go calls scanConfigToml/fetchFromEnv to check presence at scan time,
//and resolveStripeValue below calls the same underlying logic again, fresh,
//whenever Validate/GetActivity/RiskModifiers need the real value. The value is
//never stored on Credential.Metadata at any point. Only source information is.
//See discovery.go's const block
//
//resolveStripeValue re-fetches cred's value fresh, dispatching on
//metaSourceMethod (set at discovery time). ctx is accepted for signature
//consistency with the other providers' resolvers, though neither fetch path
//below is a network call
func resolveStripeValue(ctx context.Context,
	cred models.Credential) (string, error) {

	method, ok := cred.Metadata[metaSourceMethod]
	if !ok || method == "" {

		return "",
		fmt.Errorf("credential missing %s in Metadata", metaSourceMethod)

	}

	switch method {

	case "env":
		envVar, ok := cred.Metadata[metaSourceEnvVar]
		if !ok || envVar == "" {

			return "",
			fmt.Errorf("credential missing %s in Metadata", metaSourceEnvVar)

		}
		value, ok := fetchFromEnv(envVar)
		if !ok {

			return "", fmt.Errorf("stripe: %s is no longer set", envVar)

		}
		return value, nil

	case "config_toml":
		path, ok := cred.Metadata[metaSourceFilePath]
		if !ok || path == "" {

			return "",
			fmt.Errorf("credential missing %s in Metadata", metaSourceFilePath)

		}
		section, ok := cred.Metadata[metaSourceSection]
		if !ok {

			return "",
			fmt.Errorf("credential missing %s in Metadata", metaSourceSection)

		}
		key, ok := cred.Metadata[metaSourceKey]
		if !ok || key == "" {

			return "",
			fmt.Errorf("credential missing %s in Metadata", metaSourceKey)

		}
		entries, err := scanConfigToml(path)
		if err != nil {

			return "", err

		}
		for _, entry := range entries {

			if entry.section == section && entry.key == key {

				return entry.value, nil

			}

		}
		return "", fmt.Errorf("stripe: %s [%s, %s] no longer present in %s", path, section, key, path)

	default:
		return "",
		fmt.Errorf("stripe: unrecognized %s %q", metaSourceMethod, method)

	}

}

func fetchFromEnv(envVar string) (string, bool) {

	value := os.Getenv(envVar)
	if value == "" {

		return "", false

	}
	return value, true

}

//configTomlEntry is one key = value pair found under a [section] in
//config.toml, before classification. Used both by discovery.go (to build
//Credentials) and resolveStripeValue above (to re-locate a specific value)
type configTomlEntry struct {

	section string
	key string
	value string

}

//scanConfigToml does a minimal, targeted read of the Stripe CLI's config.toml,
//returning every "key = value" pair found under any [section] header,
//unfiltered. Deliberately not a full TOML parser. See discovery.go's doc
//comment on discoverFromConfigToml for why. A missing file returns (nil, nil);
//not an error
func scanConfigToml(path string) ([]configTomlEntry, error) {

	f, err := os.Open(path)
	if os.IsNotExist(err) {

		return nil, nil

	}
	if err != nil {

		return nil, fmt.Errorf("stripe: opening %s: %w", path, err)

	}
	defer f.Close()

	var entries []configTomlEntry
	currentSection := "default"

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {

			currentSection = strings.Trim(line, "[]")
			continue

		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {

			continue

		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"`)

		entries = append(entries, configTomlEntry{

			section: currentSection,
			key: key,
			value: value,

		})

	}
	if err := scanner.Err(); err != nil {

		return nil, fmt.Errorf("stripe: reading %s: %w", path, err)

	}

	return entries, nil

}