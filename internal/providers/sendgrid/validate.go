package sendgrid

import (

	"context"  //carries cancellation/deadline signals through function calls
	"encoding/json"  //parsing the JSON response from GET /v3/scopes and error bodies
	"fmt"  //string formatting and building error messages
	"io"  //reading raw response bodies
	"net/http"  //making HTTP requests to SendGrid's API
	"strings"  //string manipulation
	"time"  //recording when the check happened

	"github.com/southwickio/deadkey/internal/models"

)

//SendGrid's own official support documentation ("4XX API Errors and
//Troubleshooting Suggestions") documents two distinct, named 401 conditions
//beyond a plain bad API key, both meaning "this account can't do anything right
//now for a reason unrelated to whether this specific key is correct":
//  1. "Account Disabled": the account was suspended, banned, or deactivated by
//     SendGrid's Consumer Trust team (fraud/abuse/ToS violation)
//  2. Error 60603, "Maximum credits exceeded": the account is frozen or capped
//     for a billing/plan reason (expired trial, unpaid upgrade, declined
//     payment method). Confirmed via multiple independent, current sources
//     including SendGrid's own support article and real integration reports,
//     consistently as HTTP 401
//
//SendGrid's 401 error bodies are not confirmed to follow one single fixed JSON
//shape across all cases. errorMessageText below defensively handles most cases,
//falling back to the raw body text if neither shape parses, so a shape this
//provider hasn't seen yet still gets checked rather than silently passed over
//
//The literal text for condition #1 is confirmed only at the level of SendGrid's
//own support-article label ("Account Disabled"/"Disabled Account"). This has
//not been confirmed against the literal JSON message field of a real suspended
//account's response, since that isn't published anywhere findable. Matched here
//via a case-insensitive substring search for terms SendGrid's own documentation
//uses to describe this condition
const maxCreditsExceededPhrase = "maximum credits exceeded"

var accountDisabledPhrases = []string{"account disabled", "account was suspended", "account has been suspended", "banned", "deactivated"}

//Validate checks whether cred is alive. Behavior differs by subtype
//
//API keys: calls GET /v3/scopes with the key as a Bearer token. Confirmed real
//and self-referential per SendGrid's own docs: "This endpoint returns all the
//scopes assigned to the key you use to authenticate with it"; meaning a key can
//always check itself, no separate permission needed. As a side effect, this
//also retrieves the key's granted scopes for risk_modifiers.go, at no extra API
//call cost. SendGrid's own docs for this endpoint document "Scopes forbidden"
//and "Scopes not found" as real possible responses, meaning a 403/404 here is
//not purely theoretical even for a self-referential call. An unexpected
//non-200/401 response here is treated as "couldn't determine," not as proof the
//key is dead
//
//Legacy username/password: attempts HTTP Basic Auth against the same
//GET /v3/scopes endpoint. This is LESS confirmed than the API key path.
//SendGrid's documentation confirms Basic Auth is accepted specifically "when
//updating a key with a user scope" (a PATCH operation), not explicitly for this
//GET endpoint. Using it here as a read-only liveness probe is a reasonable
//extension, not a directly documented use case.
//
//A 401 response on either path is not treated as a single bucket. See
//classify401 for the breakdown between a genuinely bad credential and an
//account-level condition (suspended/banned, or billing-frozen)
func (p *Provider) Validate(ctx context.Context, 
	cred models.Credential) (models.ValidationResult, error) {

	switch cred.Subtype {

	case subtypeAPIKey:
		return validateAPIKey(ctx, cred)
	case subtypeLegacyCredentials:
		return validateLegacyCredentials(ctx, cred)
	default:
		return models.ValidationResult{}, 
		fmt.Errorf("sendgrid: unrecognized credential subtype %q", cred.Subtype)

	}

}

func validateAPIKey(ctx context.Context, 
	cred models.Credential) (models.ValidationResult, error) {

	value, err := resolveSendGridAPIKey(cred)
	if err != nil {

		return models.ValidationResult{}, err

	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("sendgrid: building request: %w", err)

	}
	req.Header.Set("Authorization", "Bearer "+value)

	resp, err := http.DefaultClient.Do(req)
	checkedAt := time.Now()
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("sendgrid: calling GET /v3/scopes: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {

	case http.StatusOK:
		//Capture scopes as a side effect for risk_modifiers.go. See package doc
		//comment on why this costs no extra API call
		var out struct {

			Scopes []string `json:"scopes"`

		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err == nil {

			cred.Metadata[metaScopes] = strings.Join(out.Scopes, ",")

		}
		return models.ValidationResult{

			Status: models.ValidationValid,
			CheckedAt: checkedAt,

		}, nil
	case http.StatusUnauthorized:
		return classify401(resp, checkedAt)
	default:
		//Includes 403 ("Scopes forbidden") and 404 ("Scopes not found"), both
		//documented by SendGrid as real possible responses here. Ambiguous
		//evidence, not a confirmed-dead signal. See doc comment above
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{}, fmt.Errorf("sendgrid: unexpected status %d calling GET /v3/scopes: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

}

func validateLegacyCredentials(ctx context.Context,
	cred models.Credential) (models.ValidationResult, error) {

	username, password, err := resolveSendGridLegacyCredentials(cred)
	if err != nil {

		return models.ValidationResult{}, err

	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("sendgrid: building request: %w", err)

	}
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req)
	checkedAt := time.Now()
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("sendgrid: calling GET /v3/scopes with Basic Auth: %w", err)

	}
	defer resp.Body.Close()

	switch resp.StatusCode {

	case http.StatusOK:
		return models.ValidationResult{

			Status: models.ValidationValid,
			CheckedAt: checkedAt,

		}, nil
	case http.StatusUnauthorized:
		return classify401(resp, checkedAt)
	default:
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{}, fmt.Errorf("sendgrid: unexpected status %d validating legacy credentials: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

}

//classify401 distinguishes SendGrid's documented account-level 401 conditions
//(suspended/banned, or billing-frozen) from a genuinely bad credential.
//Checked in order: billing-frozen first (its literal message text IS
//confirmed via multiple independent real examples), then suspended/banned
//(best-effort phrase match - see accountDisabledPhrases's doc comment for why
//this one is less certain), then fall through to the original
//ValidationInvalid behavior for anything else, including a plain wrong key
func classify401(resp *http.Response, checkedAt time.Time) (models.ValidationResult, error) {

	body, _ := io.ReadAll(resp.Body)
	text := strings.ToLower(errorMessageText(body))

	if strings.Contains(text, maxCreditsExceededPhrase) {

		return models.ValidationResult{

			Status: models.ValidationAccountInactive,
			CheckedAt: checkedAt,
			ErrorDetail: strings.TrimSpace(string(body)),

		}, nil

	}

	for _, phrase := range accountDisabledPhrases {

		if strings.Contains(text, phrase) {

			return models.ValidationResult{

				Status: models.ValidationAccountInactive,
				CheckedAt: checkedAt,
				ErrorDetail: strings.TrimSpace(string(body)),

			}, nil

		}

	}

	return models.ValidationResult{

		Status: models.ValidationInvalid,
		CheckedAt: checkedAt,
		ErrorDetail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),

	}, nil

}

//errorMessageText defensively extracts human-readable error text from a
//SendGrid error body, regardless of which of the two real shapes it's in (see
//this file's package-level doc comment). Falls back to the raw body text if
//neither known shape parses, rather than returning nothing; a shape this
//provider hasn't seen yet still gets checked by classify401's substring
//matching above, instead of being silently skipped
func errorMessageText(body []byte) string {

	var structured struct {

		Errors []struct {

			Message string `json:"message"`

		} `json:"errors"`

	}
	if err := json.Unmarshal(body, &structured); err == nil && len(structured.Errors) > 0 {

		var parts []string
		for _, e := range structured.Errors {

			parts = append(parts, e.Message)

		}
		return strings.Join(parts, " ")

	}

	var flat struct {

		Message string   `json:"message"`
		Errors  []string `json:"errors"`

	}
	if err := json.Unmarshal(body, &flat); err == nil && (len(flat.Errors) > 0 || flat.Message != "") {

		return flat.Message + " " + strings.Join(flat.Errors, " ")

	}

	return string(body)

}