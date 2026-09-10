package aws

import (

	"bufio"  //buffered reading, used to scan the credentials file line by line
	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"os"  //reading env vars, opening files, finding the home directory
	"path/filepath"  //building file paths correctly across operating systems 
	"strings"  //string manipulation
	
	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//CredentialSubtype used for every AWS credential this provider produces. A
//distinct subtype (e.g. for session tokens) can be added later without touching
//the shared model. See models.CredentialSubtype's doc comment
const subtypeAccessKey models.CredentialSubtype = "access_key"

//Metadata keys this provider writes onto Credential.Metadata. Declared here,
//not as raw string literals scattered through the file, per credential.go's
//guidance that each provider should define its own constants for the keys it
//writes
//
//Deliberately absent from this list: the secret access key. It is never written
//to Metadata, because Metadata lives on Credential, which is embedded in
//CredentialAssessment. The same structure written to local SQLite and used as
//the basis for cloud sync. Storing the secret there would risk it being
//persisted to disk or serialized toward cloud sync, which would break this
//project's core plaintext-never-leaves-the-machine principle. Instead, the
//secret is re-read fresh from its original source (file or env var) only at the
//moment Validate/GetActivity/RiskModifiers actually need it. See secret.go
const (

	//Which named profile this key came from (file discovery only)
	metaProfile = "aws_profile"

	//Needed by Validate/GetActivity/RiskModifiers to identify which key to
	//check
	metaAccessKeyID = "aws_access_key_id"

	//Which file this credential came from (file discovery only). Needed to
	//re-read the secret later, never the secret itself
	metaCredentialsFilePath = "aws_credentials_file"

)

//Discover finds AWS access keys via two independent methods:
//  1. Reading the standard shared credentials file (INI format), which AWS's
//     own CLI and SDKs use by default. This is DiscoveryExact. The file format
//     unambiguously labels each value's purpose.
//     Docs: docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
//  2. Reading the AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment
//     variables, which the AWS CLI and SDKs also honor. This is
//     DiscoveryPatternMatched per discovery_config.go's classification: even
//     though an access key's shape is fairly distinctive, an env var carries no
//     structural guarantee that its value is a credential at all. We're
//     inferring purpose from a shape, not reading a self-describing format
//
//A missing credentials file is not an error. Most machines simply won't have
//one. A file that exists but fails to parse IS an error, since that indicates
//something is actually wrong (permissions, corruption) rather than "nothing to
//find here"
func (p *Provider) Discover(ctx context.Context, 
	cfg providers.DiscoveryConfig) ([]models.Credential, error) {

	var found []models.Credential

	paths := cfg.Paths
	if len(paths) == 0 {
		
		home, err := os.UserHomeDir()
		if err != nil {
		
			return nil, fmt.Errorf("aws: determining home directory for default credentials path: %w", err)
		
		}
		
		paths = []string{filepath.Join(home, ".aws", "credentials")}
	
	}

	for _, path := range paths {
	
		fromFile, err := discoverFromCredentialsFile(path)
		if err != nil {
	
			return nil, err
	
		}
	
		found = append(found, fromFile...)
	
	}

	if fromEnv, ok := discoverFromEnv(); ok {
	
		found = append(found, fromEnv)
	
	}

	return found, nil

}

//discoverFromCredentialsFile parses a shared credentials file (INI format:
//[profile-name] sections, each with aws_access_key_id/aws_secret_access_key
//lines). Returns one Credential per profile found. A missing file returns (nil,
//nil). Not an error, see Discover's doc comment above
func discoverFromCredentialsFile(path string) ([]models.Credential, error) {

	f, err := os.Open(path)
	if os.IsNotExist(err) {
	
		return nil, nil
	
	}
	if err != nil {
	
		return nil, fmt.Errorf("aws: opening credentials file %s: %w", 
		path, 
		err)
	
	}
	defer f.Close()

	var found []models.Credential
	var currentProfile string
	var currentAccessKeyID string

	//Iterate through the file line by line
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		
			//Starting a new profile section. Flush whatever we collected for
			//the previous one first
			if currentProfile != "" && currentAccessKeyID != "" {

				found = append(found, buildFileCredential(path, 
					currentProfile, 
					currentAccessKeyID))
			
			}
			currentProfile = strings.Trim(line, "[]")
			currentAccessKeyID = ""
			continue

		}

		if key, value, ok := strings.Cut(line, "="); ok {
			
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key == "aws_access_key_id" {
			
				currentAccessKeyID = value
			
			}

		}

	}

	if err := scanner.Err(); err != nil {
	
		return nil, fmt.Errorf("aws: reading credentials file %s: %w", 
		path, 
		err)
	
	}

	// Flush the last profile in the file.
	if currentProfile != "" && currentAccessKeyID != "" {
	
		found = append(found, buildFileCredential(path, 
			currentProfile, 
			currentAccessKeyID))

	}

	return found, nil

}

func buildFileCredential(path, profile, accessKeyID string) models.Credential {
	
	return models.Credential{
	
		Provider: "aws",
		Subtype: subtypeAccessKey,
		Location: fmt.Sprintf("%s [%s profile]", path, profile),
		DiscoveryConfidence: models.DiscoveryExact,

		//An AWS access key ID is safe to use as-is: it is designed to be
		//non-secret (AWS itself displays it unmasked in the console and CLI
		//output), so it's a reliable way to recognize this same credential
		//again later even if it moves to a different profile/file/env var.
		//See models.Credential.Identifier's doc comment
		Identifier: accessKeyID,

		Metadata: map[string]string{
	
			metaProfile: profile,
			metaAccessKeyID: accessKeyID,
			metaCredentialsFilePath: path,

		},

	}

}

//discoverFromEnv checks AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY. Both must be
//present. A lone access key ID with no secret isn't a usable credential.
//Returns ok=false if either is missing, rather than an error: an unconfigured
//environment is the normal case, not a failure
func discoverFromEnv() (models.Credential, bool) {

	accessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	secretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if accessKeyID == "" || secretKey == "" {
	
		return models.Credential{}, false

	}


	return models.Credential{
	
		Provider: "aws",
		Subtype: subtypeAccessKey,
		Location: "env:AWS_ACCESS_KEY_ID",
		DiscoveryConfidence: models.DiscoveryPatternMatched,

		//See buildFileCredential's comment on Identifier above
		Identifier: accessKeyID,

		Metadata: map[string]string{

			metaAccessKeyID: accessKeyID,

		},

	}, true

}