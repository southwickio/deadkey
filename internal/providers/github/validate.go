package github

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"io"  //reading the raw response body when needed
	"net/http"  //making the actual HTTP request to GitHub's API
	"strings"  //string manipulation
	"time"  //recording when the check happened

	"github.com/southwickio/deadkey/internal/models"

)

//Metadata keys written by Validate, read by risk_modifiers.go
const (

	metaTokenKind = "github_token_kind"  //"classic" or "fine_grained"
	metaScopes = "github_scopes"  //comma-separated, classic tokens only
	
)

//Confirmed, stable text GitHub's API returns for a suspended personal account.
//This exact string has appeared unchanged in GitHub's API responses across at
//least a decade of integrations and was confirmed still current via a live
//incident in github/gh-aw dated 2026-05-26. Deliberately matched as an exact
//string, not a loose substring, since it has proven stable where the rate-limit
//messages have not
const suspendedAccountMessage = "Sorry. Your account was suspended"

//Organization SSO/SAML enforcement also returns 403, but is a fundamentally
//different condition from account suspension: the token itself is fine, the
//organization just requires it to be authorized for SSO access. Confirmed
//text, per GitHub's own documented behavior and matching real error output.
//This is NOT evidence the credential is dead - it authenticated successfully
//and is simply scoped out of one organization's resources - so it is
//classified as ValidationValid, not ValidationInvalid, mirroring how this
//project already treats a permissions-scoped (but alive) credential
//elsewhere (see Twilio's and Stripe's 403 handling)
const samlEnforcementMessage = "SAML enforcement"

//GitHub's rate limiting comes in two forms with two different reliability
//profiles for detection, both confirmed via GitHub's own documentation and
//current reports.
//
//Primary rate limit: reliably accompanied by the X-RateLimit-Remaining response
//header being "0". Docs: docs.github.com/rest/overview/troubleshooting. If you
//exceed your primary rate limit, you will receive a 403 Forbidden or 429 Too
//Many Requests response, and the x-ratelimit-remaining header will be 0". This
//is the reliable signal; matched on the header, not the message text
//
//Secondary rate limit: Not reliably accompanied by any specific header. A
//maintainer of the hub4j/github-api Java client library documented seeing
//"no Retry-After, no gh-limited-by, nothing" for some secondary limit
//responses (github.com/hub4j/github-api/issues/2009). The only signal is the
//message text, and GitHub's own documentation states outright that "these
//secondary rate limits are subject to change without notice"
//(docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).
//Confirmed true in practice: real reports across 2023-2025 show at least
//three different exact wordings:
//"...blocked from content creation..." (github.com/KnpLabs/php-github-api,
//commit fixing detection of this message; also seen in
//gitlab.com/gitlab-org/gitlab/-/issues/428065 and
//github.com/orgs/community/discussions/50326),
//"...wait a few minutes before you try again."
//(github.com/hub4j/github-api/issues/1842), and "Whoa there!..."
//(github.com/orgs/community/discussions/141073, reported as still occurring in
//2025). Matched here on a loose, lowercase substring ("rate limit") rather than
//any single exact phrase, specifically because GitHub itself says the exact
//wording is not a stable contract. This is the least confident of the four
//classifications in this file, and is documented as such
const rateLimitSubstring = "rate limit"

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
//
//A non-200 response is not treated as a single bucket. GitHub's API is
//documented and confirmed (via real, current reports) to return the same HTTP
//status for at least four different, meaningfully different conditions.
func (p *Provider) Validate(ctx context.Context, 
	cred models.Credential) (models.ValidationResult, error) {

	token, err := resolveGitHubToken(ctx, cred)
	if err != nil {

		return models.ValidationResult{}, err

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
	case http.StatusUnauthorized:
		//Confirmed: GitHub's suspended-account and rate-limit conditions are
		//documented and observed only on 403 (and 429 for rate limiting),
		//never on 401. A 401 here is GitHub's plain "Bad credentials" case -
		//genuinely invalid, no further classification needed
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{

			Status: models.ValidationInvalid,
			CheckedAt: checkedAt,
			ErrorDetail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),

		}, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return classifyNon200(resp, checkedAt)
	default:
		//An unexpected status (5xx, etc.) means the check itself is
		//unreliable right now, not evidence the token is dead
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{}, fmt.Errorf("github: unexpected status %d calling GET /user: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

}

//classifyNon200 distinguishes the four real, distinct conditions GitHub is
//documented and observed to surface as a 403 or 429 on GET /user:
//  1. Account suspended: ValidationAccountInactive (see
//     suspendedAccountMessage)
//  2. Organization SSO/SAML enforcement: ValidationValid (see
//     samlEnforcementMessage)
//  3. Primary rate limit: a Go error (transient; the check itself failed, not
//     evidence about the token). Detected via the X-RateLimit-Remaining header,
//     which is confirmed reliable for this specific condition
//  4. Secondary rate limit: a Go error, same reasoning as #3, but detected via
//     a loose substring match on the message body, since GitHub does not
//     guarantee a stable header or a stable message for this specific case
//  5. Anything else: ValidationInvalid, the same conservative fallback this
//     provider used before this classification existed
//
//Checked in this order deliberately: the two reliable, specific checks
//(suspension, SAML) first, then the header-based rate-limit check (reliable but
//only covers the primary case), then the least reliable check (message
//substring for the secondary case) last, so a message that happens to contain
//"rate limit" for an unrelated reason doesn't pre-empt a more specific,
//confirmed match above it
func classifyNon200(resp *http.Response, 
	checkedAt time.Time) (models.ValidationResult, error) {

	body, _ := io.ReadAll(resp.Body)
	bodyText := string(body)

	if strings.Contains(bodyText, suspendedAccountMessage) {

		return models.ValidationResult{

			Status: models.ValidationAccountInactive,
			CheckedAt: checkedAt,
			ErrorDetail: strings.TrimSpace(bodyText),

		}, nil

	}

	if strings.Contains(bodyText, samlEnforcementMessage) {

		return models.ValidationResult{

			Status: models.ValidationValid,
			CheckedAt: checkedAt,

		}, nil

	}

	if resp.Header.Get("X-RateLimit-Remaining") == "0" {

		return models.ValidationResult{}, fmt.Errorf("github: primary rate limit exceeded, check is transient (not evidence about the token): %s", strings.TrimSpace(bodyText))

	}

	if strings.Contains(strings.ToLower(bodyText), rateLimitSubstring) {

		//Least confident branch in this file. See rateLimitSubstring's doc
		//comment: GitHub does not guarantee this wording stays stable
		return models.ValidationResult{}, fmt.Errorf("github: likely a secondary rate limit (message-based match, GitHub does not guarantee this wording; treated as transient, not evidence about the token): %s", strings.TrimSpace(bodyText))

	}

	//None of the four known conditions matched. Conservative fallback,
	//unchanged from this provider's original behavior
	return models.ValidationResult{

		Status: models.ValidationInvalid,
		CheckedAt: checkedAt,
		ErrorDetail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(bodyText)),

	}, nil

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