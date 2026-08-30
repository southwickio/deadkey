package github

import (

	"bufio"  //reads files/command output line-by-line or word-by-word
	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"os"  //reading env vars, opening files, finding the home directory
	"os/exec"  //running external commands (gh, git) as subprocesses
	"path/filepath"  //building file paths correctly across operating systems
	"strings"  //string manipulation (trimming, splitting, prefix checks)

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

const subtypePersonalAccessToken models.CredentialSubtype = "personal_access_token"

//Metadata keys this provider writes onto Credential.Metadata
const (

	metaToken = "github_token"

)

//Discover finds GitHub personal access tokens via six independent methods, each
//verified against real, documented behavior. Deliberately comprehensive: a
//token holder might authenticate to GitHub through any one of several
//completely different tools (gh CLI, plain git, a manually-set env var), and
//each leaves a token in a different place:
//  1. GITHUB_TOKEN/GH_TOKEN environment variables: DiscoveryPatternMatched.
//     Confirmed real and commonly used, including as the conventional name
//     for tokens manually exported for CI or scripting
//  2. gh CLI's own stored auth, via `gh auth token`: DiscoveryExact. Modern gh
//     versions store the token in the OS keyring by default, not in a plain
//     file (confirmed: docs and real-world reports show keyring-first storage
//     since gh 2.24, with hosts.yml as a legacy fallback only). Rather than
//     reverse-engineer gh's private, unconfirmed internal keyring
//     service/username naming (a real unknown we could not verify for
//     Windows/Linux), this shells out to gh's own official, documented command,
//     which resolves the token correctly regardless of where gh actually stored
//     it, on any OS. Requires gh to be installed and on PATH; a safe assumption
//     for anyone who has ever run `gh auth login`
//  3. ~/.config/gh/hosts.yml, read directly: DiscoveryExact. A fallback for
//     machines with a leftover hosts.yml but no gh binary currently on PATH
//     (for example: gh was uninstalled after logging in, or the file was copied
//     from another machine). Only catches the legacy plaintext case; a
//     keyring-backed hosts.yml has no token in the file itself, so this path
//     naturally finds nothing there and moves on
//  4. ~/.netrc: DiscoveryExact. A long-standing, well-documented mechanism
//     curl/libcurl (and therefore git over HTTPS) uses for stored credentials:
//     "machine github.com login <user> password <token>". Confirmed real and
//     commonly used specifically with GitHub PATs as the password field
//  5. ~/.git-credentials, read directly: DiscoveryExact. Git's own plaintext
//     "store" credential helper, confirmed real and documented: one URL per
//     line, "https://username:TOKEN@github.com"
//  6. `git credential fill`, for any other configured git credential helper:
//     DiscoveryExact. Covers OS-keyring-backed helpers (macOS Keychain,
//     Windows Credential Manager, Linux Secret Service) and Git Credential
//     Manager, all of which store tokens outside any file deadkey could read
//     directly. Mirrors method 2's approach: use git's own official, documented
//     interface rather than each backend's private storage format
//A missing file/command/env var at any of these is not an error. Most machines
//will only have some of these configured, and that's the normal case. A file
//that exists but fails to parse, or a command that fails for a reason other
//than "not found," is a real error worth surfacing
func (p *Provider) Discover(ctx context.Context, 
	cfg providers.DiscoveryConfig) ([]models.Credential, error) {

	var found []models.Credential

	if cred, ok := discoverFromEnv(); ok {

		found = append(found, cred)

	}

	if cred, ok := discoverFromGHCLI(ctx); ok {

		found = append(found, cred)

	}

	hostsYMLPaths := cfg.Paths
	if len(hostsYMLPaths) == 0 {

		if home, err := os.UserHomeDir(); err == nil {

			hostsYMLPaths = []string{filepath.Join(home, ".config", "gh", "hosts.yml")}

		}

	}
	for _, path := range hostsYMLPaths {

		if cred, ok, err := discoverFromHostsYML(path); err != nil {

			return nil, err

		} else if ok {

			found = append(found, cred)

		}

	}

	if cred, ok, err := discoverFromNetrc(); err != nil {

		return nil, err

	} else if ok {

		found = append(found, cred)

	}

	if cred, ok, err := discoverFromGitCredentialsFile(); err != nil {

		return nil, err

	} else if ok {

		found = append(found, cred)

	}

	if cred, ok := discoverFromGitCredentialHelper(ctx); ok {

		found = append(found, cred)

	}

	return found, nil

}

func discoverFromEnv() (models.Credential, bool) {

	for _, envVar := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {

		if token := os.Getenv(envVar); token != "" {

			return models.Credential{

				Provider: "github",
				Subtype: subtypePersonalAccessToken,
				Location: "env:" + envVar,
				DiscoveryConfidence: models.DiscoveryPatternMatched,
				Metadata: map[string]string{metaToken: token},

			}, true

		}

	}
	return models.Credential{}, false

}

//discoverFromGHCLI shells out to `gh auth token`, GitHub's own documented
//command for retrieving the currently active token regardless of where gh
//stored it. A missing gh binary, or gh reporting no active session, is not an
//error. It simply means this discovery method found nothing
func discoverFromGHCLI(ctx context.Context) (models.Credential, bool) {

	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err != nil {

		return models.Credential{}, false

	}
	token := strings.TrimSpace(string(out))
	if token == "" {

		return models.Credential{}, false

	}
	return models.Credential{

		Provider: "github",
		Subtype: subtypePersonalAccessToken,
		Location: "gh CLI (gh auth token)",
		DiscoveryConfidence: models.DiscoveryExact,
		Metadata: map[string]string{metaToken: token},

	}, true

}

//discoverFromHostsYML does a minimal, targeted read of gh's hosts.yml looking
//only for a plaintext "oauth_token:" line. Deliberately not a full YAML parser.
//The file's only field this provider needs is the token itself, and a full YAML
//dependency is unwarranted for one field. A missing file is not an error (most
//machines using the modern keyring-backed gh won't have a plaintext token in
//this file at all)
func discoverFromHostsYML(path string) (models.Credential, bool, error) {

	f, err := os.Open(path)
	if os.IsNotExist(err) {

		return models.Credential{}, false, nil

	}
	if err != nil {

		return models.Credential{}, 
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
			return models.Credential{

				Provider: "github",
				Subtype: subtypePersonalAccessToken,
				Location: fmt.Sprintf("%s (oauth_token)", path),
				DiscoveryConfidence: models.DiscoveryExact,
				Metadata: map[string]string{metaToken: token},

			}, true, nil

		}

	}
	if err := scanner.Err(); err != nil {

		return models.Credential{}, false, fmt.Errorf("github: reading %s: %w", path, err)

	}
	return models.Credential{}, false, nil

}

//discoverFromNetrc looks for a "machine github.com ... password <token>" entry.
//Format confirmed against curl/git's own documented .netrc syntax
func discoverFromNetrc() (models.Credential, bool, error) {

	home, err := os.UserHomeDir()
	if err != nil {

		return models.Credential{}, 
		false, 
		fmt.Errorf("github: determining home directory: %w", err)

	}
	path := filepath.Join(home, ".netrc")

	f, err := os.Open(path)
	if os.IsNotExist(err) {

		return models.Credential{}, false, nil

	}
	if err != nil {

		return models.Credential{}, 
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

		return models.Credential{},
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

				return models.Credential{

					Provider: "github",
					Subtype: subtypePersonalAccessToken,
					Location: fmt.Sprintf("%s (machine github.com)", path),
					DiscoveryConfidence: models.DiscoveryExact,
					Metadata: map[string]string{metaToken: tokens[i+1]},

				}, true, nil

			}

		}

	}
	return models.Credential{}, false, nil

}

//discoverFromGitCredentialsFile reads git's plaintext "store" helper file,
//looking for a github.com entry. Format confirmed against git's own
//documentation: one URL per line, "https://user:TOKEN@github.com"
func discoverFromGitCredentialsFile() (models.Credential, bool, error) {

	home, err := os.UserHomeDir()
	if err != nil {

		return models.Credential{}, 
		false, 
		fmt.Errorf("github: determining home directory: %w", err)

	}
	path := filepath.Join(home, ".git-credentials")

	f, err := os.Open(path)
	if os.IsNotExist(err) {

		return models.Credential{}, false, nil

	}
	if err != nil {

		return models.Credential{},
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
		return models.Credential{

			Provider: "github",
			Subtype: subtypePersonalAccessToken,
			Location: fmt.Sprintf("%s (github.com entry)", path),
			DiscoveryConfidence: models.DiscoveryExact,
			Metadata: map[string]string{metaToken: token},

		}, true, nil

	}
	if err := scanner.Err(); err != nil {

		return models.Credential{}, 
		false, 
		fmt.Errorf("github: reading %s: %w", path, err)

	}
	return models.Credential{}, false, nil

}

//discoverFromGitCredentialHelper shells out to `git credential fill`, git's own
//documented interface for resolving a credential through whichever helper is
//actually configured (OS keyring, Git Credential Manager, or otherwise). The
//same approach as discoverFromGHCLI, and for the same reason: git's own
//official command is a stable, documented contract, unlike guessing at any
//specific backend's private storage format
func discoverFromGitCredentialHelper(ctx context.Context) (models.Credential, bool) {

	cmd := exec.CommandContext(ctx, "git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	out, err := cmd.Output()
	if err != nil {

		return models.Credential{}, false

	}

	var token string
	for _, line := range strings.Split(string(out), "\n") {

		if key, value, ok := strings.Cut(line, "="); ok && key == "password" {

			token = strings.TrimSpace(value)

		}

	}
	if token == "" {

		return models.Credential{}, false

	}
	return models.Credential{

		Provider: "github",
		Subtype: subtypePersonalAccessToken,
		Location: "git credential helper (git credential fill)",
		DiscoveryConfidence: models.DiscoveryExact,
		Metadata: map[string]string{metaToken: token},

	}, true

}