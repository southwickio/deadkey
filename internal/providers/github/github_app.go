package github

import (

	"context"  //carries cancellation/deadline signals through function calls
	"crypto/rsa"  //the RSA private-key type used to sign the App's JWT
	"encoding/json"  //parsing JSON responses from GitHub's API
	"fmt"  //string formatting and building error messages
	"io"  //reading raw response bodies
	"net/http"  //making HTTP requests to GitHub's API
	"os"  //reading the private key file from disk
	"strings"  //string manipulation (trimming)
	"time"  //building timestamps for the JWT and API responses

	"github.com/golang-jwt/jwt/v5"

	"github.com/southwickio/deadkey/internal/models"

)

//getActivityViaGitHubApp implements Mode 2: authenticating as a GitHub App to
//call the org-level personal-access-tokens endpoint, which is the only
//confirmed way to retrieve token_last_used_at for a fine-grained token (see
//activity.go's doc comment for why this can't be done as the personal access
//token itself)
//
//GitHub App authentication is a two-step exchange, per GitHub's own docs
//docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app:
//  1. Sign a short-lived JWT with the App's private key, identifying the App by
//     its App ID
//  2. Exchange that JWT for an installation access token, scoped to this
//     specific org's installation of the App
//The installation access token is then used as a normal Bearer token for the
//actual API call
func getActivityViaGitHubApp(ctx context.Context, 
	cred models.Credential, 
	appID, 
	privateKeyPath, 
	org string) (models.ActivityResult, error) {

	installationToken, err := getGitHubAppInstallationToken(ctx, appID, privateKeyPath, org)
	if err != nil {

		return models.ActivityResult{}, 
		fmt.Errorf("github: authenticating as GitHub App: %w", err)

	}

	tokenID, ok := cred.Metadata[metaTokenID]
	if !ok || tokenID == "" {

		//We don't yet have this token's org-assigned numeric ID, only the raw
		//token value. token_last_used_at is looked up by token_id, not by the
		//token string itself. The org endpoint never accepts the raw token.
		//Resolving a raw fine-grained token to its token_id is not exposed by
		//any confirmed GitHub API as of this research pass. This is a real,
		//honest limitation: Mode 2 can list an org's tokens and their last-used
		//data, but matching a specific locally-discovered token to its entry in
		//that list requires a shared identifier this provider does not
		//currently have. Reported as Unavailable rather than guessed.
		return models.ActivityResult{

			Quality: models.ActivityUnavailable,
			Source:  "GitHub App configured, but this token could not be matched to an org token_id. See comment in github_app.go for the specific limitation",

		}, nil

	}

	return lookupTokenLastUsed(ctx, installationToken, org, tokenID)

}

//Metadata key for a fine-grained token's org-assigned numeric ID, when known.
//Not populated by any current discovery method. See the comment in
//getActivityViaGitHubApp above
const metaTokenID = "github_token_id"

func getGitHubAppInstallationToken(ctx context.Context, 
	appID, 
	privateKeyPath, 
	org string) (string, error) {

	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {

		return "",
		fmt.Errorf("reading private key file %s: %w", privateKeyPath, err)

	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {

		return "", fmt.Errorf("parsing private key: %w", err)

	}

	appJWT, err := buildAppJWT(appID, privateKey)
	if err != nil {

		return "", fmt.Errorf("building App JWT: %w", err)

	}

	installationID, err := getInstallationIDForOrg(ctx, appJWT, org)
	if err != nil {

		return "", fmt.Errorf("resolving installation for org %s: %w", org, err)

	}

	return exchangeForInstallationToken(ctx, appJWT, installationID)

}

func buildAppJWT(appID string, key *rsa.PrivateKey) (string, error) {

	now := time.Now()
	claims := jwt.RegisteredClaims{

		Issuer: appID,
		IssuedAt: jwt.NewNumericDate(now.Add(-60 * time.Second)),  //clock drift tolerance, per GitHub's own guidance
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),  //GitHub's max is 10 minutes

	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)

}

func getInstallationIDForOrg(ctx context.Context, 
	appJWT, 
	org string) (int64, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/orgs/"+org+"/installation", nil)
	if err != nil {

		return 0, err

	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+appJWT)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return 0, err

	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {

		body, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	
	}

	var out struct {

		ID int64 `json:"id"`

	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {

		return 0, err

	}
	return out.ID, nil

}

func exchangeForInstallationToken(ctx context.Context, 
	appJWT string, 
	installationID int64) (string, error) {

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {

		return "", err

	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+appJWT)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return "", err

	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {

		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

	var out struct {

		Token string `json:"token"`

	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {

		return "", err

	}
	return out.Token, nil

}

//lookupTokenLastUsed calls GET /orgs/{org}/personal-access-tokens filtered to a
//specific token_id, per GitHub's documented API
//(docs.github.com/en/rest/orgs/personal-access-tokens)
func lookupTokenLastUsed(ctx context.Context,
	installationToken,
	org,
	tokenID string) (models.ActivityResult, error) {

	url := fmt.Sprintf("https://api.github.com/orgs/%s/personal-access-tokens?token_id=%s", org, tokenID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {

		return models.ActivityResult{}, err

	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+installationToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return models.ActivityResult{}, err

	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {

		return models.ActivityResult{

			Quality: models.ActivityUnavailable,
			Source: "GitHub App lacks 'Personal access tokens' (read) permission on this org",

		}, nil

	}
	if resp.StatusCode != http.StatusOK {

		body, _ := io.ReadAll(resp.Body)
		return models.ActivityResult{}, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

	var results []struct {

		TokenLastUsedAt *time.Time `json:"token_last_used_at"`

	}
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {

		return models.ActivityResult{}, err

	}
	if len(results) == 0 {

		return models.ActivityResult{

			Quality: models.ActivityUnavailable,
			Source:  "token_id not found among this org's approved fine-grained tokens",

		}, nil

	}

	return models.ActivityResult{

		LastUsedAt: results[0].TokenLastUsedAt,
		Quality: models.ActivityConfirmed,
		Source: "GET /orgs/{org}/personal-access-tokens (via GitHub App)",

	}, nil

}