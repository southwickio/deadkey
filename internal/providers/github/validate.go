package github

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"io"  //reading the raw response body when needed
	"net/http"  //making the actual HTTP request to GitHub's API
	"strings"  //string manipulation (trimming, prefix checks)
	"time"  //recording when the check happened

	"github.com/southwickio/deadkey/internal/models"

)

//Metadata keys written by Validate, read by risk_modifiers.go
const (

	metaTokenKind = "github_token_kind"  //"classic" or "fine_grained"
	metaScopes = "github_scopes"  //comma-separated, classic tokens only
	
)

//Validate checks whether cred is alive by calling GET /user
//
//Docs: docs.github.com/en/rest/users/users
//Confirmed via the actual response schema that this endpoint requires no
//fine-grained permissions and works with any authenticated token (classic or
//fine-grained). This is the correct zero-permission baseline check which proves
//the token is alive without requiring the token to have any specific scope or
//permission
//
//This call also does double duty for the risk-modifier check in
//risk_modifiers.go: classic tokens return their granted scopes via the
//X-OAuth-Scopes response header (confirmed real and documented) on this same
//request. No separate API call needed. Fine-grained tokens do not populate this
//header (they use a different, granular permission model rather than broad
//scopes), which is expected, not a gap
//
//Token kind (classic vs. fine-grained) is classified here by prefix: classic
//tokens begin "ghp_", fine-grained tokens begin "github_pat_". This prefix
//scheme is GitHub's own well-known convention
func (p *Provider) Validate(ctx context.Context, 
	cred models.Credential) (models.ValidationResult, error) {

	token, ok := cred.Metadata[metaToken]
	if !ok || token == "" {

		return models.ValidationResult{},
		fmt.Errorf("credential missing %s in Metadata", metaToken)

	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {

		return models.ValidationResult{},
		fmt.Errorf("github: building request: %w", err)

	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	checkedAt := time.Now()
	if err != nil {

		//The request itself failed (network, DNS, timeout). We don't know
		//whether the token works. Per the Provider interface's contract, this
		//is a Go error, not a ValidationInvalid result
		return models.ValidationResult{},
		fmt.Errorf("github: calling GET /user: %w", err)

	}
	defer resp.Body.Close()

	//Record scopes and token kind on the credential's metadata for
	//risk_modifiers.go to use, regardless of validation outcome. Even an
	//invalid token's scope header (if present) is informational
	if scopes := resp.Header.Get("X-OAuth-Scopes"); scopes != "" {

		cred.Metadata[metaScopes] = scopes

	}
	cred.Metadata[metaTokenKind] = classifyTokenKind(token)

	switch resp.StatusCode {

	case http.StatusOK:
		return models.ValidationResult{

			Status: models.ValidationValid,
			CheckedAt: checkedAt,

		}, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{

			Status: models.ValidationInvalid,
			CheckedAt: checkedAt,
			ErrorDetail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),

		}, nil
	default:
		//An unexpected status (5xx, rate limiting, etc.) means the check itself
		//is unreliable right now, not evidence the token is dead
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{}, fmt.Errorf("github: unexpected status %d calling GET /user: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

}

//classifyTokenKind distinguishes classic from fine-grained personal access
//tokens by their prefix. Classic tokens (broad scopes, no expiration
//requirement, invisible to org admins) and fine-grained tokens (narrow
//permissions, mandatory expiration, subject to org approval policies) are
//different enough in risk profile that treating them identically would lose
//real signal. See risk_modifiers.go
func classifyTokenKind(token string) string {

	switch {

	case strings.HasPrefix(token, "github_pat_"):
		return "fine_grained"
	case strings.HasPrefix(token, "ghp_"):
		return "classic"
	default:
		//Older classic tokens predate the ghp_ prefix convention, and OAuth app
		//tokens (gho_) or other GitHub token types may appear here too. Treat
		//as classic by default (the more conservative assumption for risk
		//purposes) rather than silently skipping classification
		return "classic"

	}

}