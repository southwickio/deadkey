package github

import (

	"bufio"  //reads files/command output line-by-line or word-by-word
	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"os"  //reading env vars, opening files
	"os/exec"  //running external commands (gh, git) as subprocesses
	"strings"  //string manipulation (trimming, splitting, prefix checks)

	"github.com/southwickio/deadkey/internal/models"

)

//This file owns every actual token retrieval in the GitHub provider.
//discovery.go calls these same functions to check presence at scan time, and
//resolveGitHubToken below calls them again, fresh, whenever
//Validate/GetActivity/RiskModifiers need the real token. The token is never
//stored on Credential.Metadata at any point. Only source information
//(method + env var name or file path) is. See discovery.go's const block
//
//resolveGitHubToken re-fetches cred's token fresh, dispatching on
//metaSourceMethod (set at discovery time) to the matching fetch function
//below. This is called every time Validate/GetActivity/RiskModifiers need the
//actual token. It is never cached and never stored on Credential itself
func resolveGitHubToken(ctx context.Context, 
	cred models.Credential) (string, error) {

	method, ok := cred.Metadata[metaSourceMethod]
	if !ok || method == "" {

		return "", fmt.Errorf("credential missing %s in Metadata", metaSourceMethod)

	}

	switch method {

	case "env":
		envVar, ok := cred.Metadata[metaSourceEnvVar]
		if !ok || envVar == "" {

			return "", 
			fmt.Errorf("credential missing %s in Metadata", metaSourceEnvVar)

		}
		token, ok := fetchFromEnv(envVar)
		if !ok {

			return "", fmt.Errorf("github: %s is no longer set", envVar)

		}
		return token, nil

	case "gh_cli":
		token, ok := fetchFromGHCLI(ctx)
		if !ok {

			return "", 
			fmt.Errorf("github: gh auth token no longer returns a token")

		}
		return token, nil

	case "hosts_yml":
		path, ok := cred.Metadata[metaSourceFilePath]
		if !ok || path == "" {

			return "",
			fmt.Errorf("credential missing %s in Metadata", metaSourceFilePath)

		}
		token, ok, err := fetchFromHostsYML(path)
		if err != nil {

			return "", err

		}
		if !ok {

			return "",
			fmt.Errorf("github: %s no longer has an oauth_token", path)

		}
		return token, nil

	case "netrc":
		path, ok := cred.Metadata[metaSourceFilePath]
		if !ok || path == "" {

			return "",
			fmt.Errorf("credential missing %s in Metadata", metaSourceFilePath)

		}
		token, ok, err := fetchFromNetrc(path)
		if err != nil {

			return "", err

		}
		if !ok {

			return "",
			fmt.Errorf("github: %s no longer has a github.com entry", path)

		}
		return token, nil

	case "git_credentials_file":
		path, ok := cred.Metadata[metaSourceFilePath]
		if !ok || path == "" {

			return "",
			fmt.Errorf("credential missing %s in Metadata", metaSourceFilePath)

		}
		token, ok, err := fetchFromGitCredentialsFile(path)
		if err != nil {

			return "", err

		}
		if !ok {

			return "",
			fmt.Errorf("github: %s no longer has a github.com entry", path)

		}
		return token, nil

	case "git_credential_helper":
		token, ok := fetchFromGitCredentialHelper(ctx)
		if !ok {

			return "",
			fmt.Errorf("github: git credential fill no longer returns a token")

		}
		return token, nil

	default:
		return "",
		fmt.Errorf("github: unrecognized %s %q", metaSourceMethod, method)

	}

}

func fetchFromEnv(envVar string) (string, bool) {

	token := os.Getenv(envVar)
	if token == "" {

		return "", false

	}
	return token, true

}

func fetchFromGHCLI(ctx context.Context) (string, bool) {

	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {

		return "", false

	}
	token := strings.TrimSpace(string(out))
	if token == "" {

		return "", false

	}
	return token, true

}

//fetchFromHostsYML does a minimal, targeted read of gh's hosts.yml looking only
//for a plaintext "oauth_token:" line. Deliberately not a full YAML parser. The
//file's only field this provider needs is the token itself, and a full YAML
//dependency is unwarranted for one field. A missing file is not an error (most
//machines using the modern keyring-backed gh won't have a plaintext token in
//this file at all)
func fetchFromHostsYML(path string) (string, bool, error) {

	f, err := os.Open(path)
	if os.IsNotExist(err) {

		return "", false, nil

	}
	if err != nil {

		return "", 
		false, 
		fmt.Errorf("github: opening %s: %w", path, err)

	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())
		if key, value, ok := strings.Cut(line, ":"); ok && strings.TrimSpace(key) == "oauth_token" {

			token := strings.TrimSpace(value)
			if token == "" {

				continue

			}
			return token, true, nil

		}

	}
	if err := scanner.Err(); err != nil {

		return "", false, fmt.Errorf("github: reading %s: %w", path, err)

	}
	return "", false, nil

}

//fetchFromNetrc looks for a "machine github.com ... password <token>" entry.
//Format confirmed against curl/git's own documented .netrc syntax
func fetchFromNetrc(path string) (string, bool, error) {

	f, err := os.Open(path)
	if os.IsNotExist(err) {

		return "", false, nil

	}
	if err != nil {

		return "", 
		false, 
		fmt.Errorf("github: opening %s: %w", path, err)

	}
	defer f.Close()

	//.netrc is whitespace-tokenized, not line-oriented. So an entry may span
	//multiple lines. Read the whole file and tokenize it
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)

	var tokens []string
	for scanner.Scan() {

		tokens = append(tokens, scanner.Text())

	}
	if err := scanner.Err(); err != nil {

		return "",
		false,
		fmt.Errorf("github: reading %s: %w", path, err)

	}

	inGitHubMachine := false
	for i := 0; i < len(tokens); i++ {

		switch tokens[i] {

		case "machine":
			if i+1 < len(tokens) {

				inGitHubMachine = tokens[i+1] == "github.com"

			}
		case "password":
			if inGitHubMachine && i+1 < len(tokens) {

				return tokens[i+1], true, nil

			}

		}

	}
	return "", false, nil

}

//fetchFromGitCredentialsFile reads git's plaintext "store" helper file, looking
//for a github.com entry. Format confirmed against git's own documentation: one
//URL per line, "https://user:TOKEN@github.com"
func fetchFromGitCredentialsFile(path string) (string, bool, error) {

	f, err := os.Open(path)
	if os.IsNotExist(err) {

		return "", false, nil

	}
	if err != nil {

		return "",
		false,
		fmt.Errorf("github: opening %s: %w", path, err)

	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())
		if !strings.Contains(line, "github.com") {

			continue

		}
		//https://username:TOKEN@github.com - extract between ':' and '@'
		atIdx := strings.LastIndex(line, "@")
		if atIdx == -1 {

			continue

		}
		beforeAt := line[:atIdx]
		colonIdx := strings.LastIndex(beforeAt, ":")
		if colonIdx == -1 {

			continue

		}
		token := beforeAt[colonIdx+1:]
		if token == "" {

			continue

		}
		return token, true, nil

	}
	if err := scanner.Err(); err != nil {

		return "", 
		false, 
		fmt.Errorf("github: reading %s: %w", path, err)

	}
	return "", false, nil

}

//fetchFromGitCredentialHelper shells out to `git credential fill`, git's own
//documented interface for resolving a credential through whichever helper is
//actually configured (OS keyring, Git Credential Manager, or otherwise)
func fetchFromGitCredentialHelper(ctx context.Context) (string, bool) {

	cmd := exec.CommandContext(ctx, "git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	out, err := cmd.Output()
	if err != nil {

		return "", false

	}

	var token string
	for _, line := range strings.Split(string(out), "\n") {

		if key, value, ok := strings.Cut(line, "="); ok && key == "password" {

			token = strings.TrimSpace(value)

		}

	}
	if token == "" {

		return "", false

	}
	return token, true

}