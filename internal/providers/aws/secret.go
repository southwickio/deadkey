package aws

import (

	"bufio"  //buffered reading, used to scan the credentials file line by line
	"fmt"  //string formatting and building error messages
	"os"  //reading env vars, opening files, finding the home directory
	"strings"  //string manipulation

	"github.com/southwickio/deadkey/internal/models"

)

//resolveSecretAccessKey re-reads cred's secret access key from wherever it
//originally came from; never from Credential.Metadata, which never holds it
//(see the comment on metaCredentialsFilePath in discovery.go for why). This
//means every call to Validate/GetActivity/RiskModifiers re-reads the secret
//from disk or the environment, rather than caching it anywhere. Slightly more
//I/O, but it means the secret's only ever-persisted location remains whatever
//the user already had it in (their own credentials file or their own shell
//environment). deadkey itself never becomes a second place where it's written
//down
func resolveSecretAccessKey(cred models.Credential) (string, error) {

	accessKeyID, ok := cred.Metadata[metaAccessKeyID]
	if !ok || accessKeyID == "" {
	
		return "", fmt.Errorf("credential missing %s in Metadata",
		metaAccessKeyID)
	
	}

	//File-discovered credential: re-read the secret from the same file and
	//profile it was originally found in
	if path, ok := cred.Metadata[metaCredentialsFilePath]; ok && path != "" {

		profile := cred.Metadata[metaProfile]
		secret, err := secretFromCredentialsFile(path, profile, accessKeyID)
		if err != nil {
		
			return "", fmt.Errorf("aws: re-reading secret for profile %q from %s: %w", profile, path, err)
		
		}
		if secret == "" {
		
			return "", fmt.Errorf("aws: profile %q in %s no longer has a matching secret (credential may have changed since discovery)", profile, path)
		
		}
		return secret, nil

	}

	//Env-discovered credential: re-check the environment. If someone changed
	//AWS_ACCESS_KEY_ID between discovery and now, this correctly fails rather
	//than silently using the wrong secret
	if os.Getenv("AWS_ACCESS_KEY_ID") == accessKeyID {

		if secret := os.Getenv("AWS_SECRET_ACCESS_KEY"); secret != "" {

			return secret, nil

		}

	}

	return "", fmt.Errorf("aws: no secret access key available for %s (neither its original file nor the environment currently has it)", accessKeyID)
}

//secretFromCredentialsFile re-parses path looking specifically for profile's
//aws_secret_access_key, but only if that profile's aws_access_key_id still
//matches expectedAccessKeyID; guarding against the case where the file has
//changed since discovery ran
func secretFromCredentialsFile(path, 
	profile, 
	expectedAccessKeyID string) (string, error) {
	
	f, err := os.Open(path)
	if err != nil {
	
		return "", err
	
	}
	defer f.Close()

	var inTargetProfile bool
	var accessKeyID, secretKey string

	//Iterate through each line of the file
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
	
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
	
			if inTargetProfile {
	
				break //We've moved past the profile we cared about
	
			}
			inTargetProfile = strings.Trim(line, "[]") == profile
			continue

		}

		if !inTargetProfile {
	
			continue
	
		}

		if key, value, ok := strings.Cut(line, "="); ok {
	
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			switch key {

			case "aws_access_key_id":
				accessKeyID = value
			case "aws_secret_access_key":
				secretKey = value

			}

		}

	}
	if err := scanner.Err(); err != nil {

		return "", err

	}

	if accessKeyID != expectedAccessKeyID {

		//The profile's key changed since discovery. Don't return a mismatched
		//secret
		return "", nil

	}

	return secretKey, nil
	
}