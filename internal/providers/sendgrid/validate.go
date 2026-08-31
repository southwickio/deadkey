package sendgrid

import (

	"context"  //carries cancellation/deadline signals through function calls
	"encoding/json"  //parsing the JSON response from GET /v3/scopes
	"fmt"  //string formatting and building error messages
	"io"  //reading raw response bodies
	"net/http"  //making HTTP requests to SendGrid's API
	"strings"  //string manipulation (trimming, joining scopes into one string)
	"time"  //recording when the check happened

	"github.com/southwickio/deadkey/internal/models"

)

// Validate checks whether cred is alive. Behavior differs by subtype
//
//API keys: calls GET /v3/scopes with the key as a Bearer token. Confirmed real
//and self-referential per SendGrid's own docs: "This endpoint returns all the
//scopes assigned to the key you use to authenticate with it"; meaning a key can
//always check itself, no separate permission needed. As a side effect, this
//also retrieves the key's granted scopes for risk_modifiers.go, at no extra
//API call cost. SendGrid's own docs for this endpoint document "Scopes
//forbidden" and "Scopes not found" as real possible responses, meaning a
//403/404 here is not purely theoretical even for a self-referential call. Per
//the same ambiguous-evidence principle used for AWS's and Stripe's 403 cases,
//an unexpected non-200/401 response here is treated as "couldn't determine,"
//not as proof the key is dead
//
//Legacy username/password: attempts HTTP Basic Auth against the same
//GET /v3/scopes endpoint. This is LESS confirmed than the API key path.
//SendGrid's documentation confirms Basic Auth is accepted specifically "when
//updating a key with a user scope" (a PATCH operation), not explicitly for this
//GET endpoint. Using it here as a read-only liveness probe is a reasonable
//extension, not a directly documented use case.
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
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{

			Status: models.ValidationInvalid,
			CheckedAt: checkedAt,
			ErrorDetail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),

		}, nil
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
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{

			Status: models.ValidationInvalid,
			CheckedAt: checkedAt,
			ErrorDetail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))),

		}, nil
	default:
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{}, fmt.Errorf("sendgrid: unexpected status %d validating legacy credentials: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

}