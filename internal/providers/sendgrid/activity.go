package sendgrid

import (

	"context"  //carries cancellation/deadline signals through function calls
	"encoding/json"  //parsing the JSON response from specific endpoints
	"fmt"  //string formatting and building error messages
	"net/http"  //making HTTP requests to SendGrid's API
	"time"  //converting the response's Unix timestamp into a real time value

	"github.com/southwickio/deadkey/internal/models"

)

//GetActivity reports how "alive" the SendGrid account behind cred looks, via
//GET /v3/access_settings/activity
//
//Confirmed via SendGrid's own docs the validity of this endpoint and its
//documented last_at field (a Unix timestamp for "when the most recent access
//attempt was made")
//
//This is reported as ActivityInferred, not ActivityConfirmed, for an important
//reason: last_at is ACCOUNT-level (the most recent access to the account by any
//method: Web UI or API), not tied to this specific credential. A long-idle
//last_at is a real, meaningful signal that the account is likely dormant, but
//it cannot confirm THIS specific key was or wasn't the one used
//
//This does not apply to subtypeLegacyCredentials in the same way. A legacy
//username/password pair IS effectively the account-level credential, so an
//account-level last-used signal is a closer match for that subtype than for an
//individual scoped API key
//
//If the call fails due to a permissions gap (a real, named scope: 
//access_settings.activity.read), this degrades to ActivityUnavailable, not a Go
//error
func (p *Provider) GetActivity(ctx context.Context, 
	cred models.Credential) (models.ActivityResult, error) {

	authHeader, err := buildAuthHeader(cred)
	if err != nil {

		return models.ActivityResult{}, err

	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.sendgrid.com/v3/access_settings/activity?limit=1", nil)
	if err != nil {

		return models.ActivityResult{},
		fmt.Errorf("sendgrid: building request: %w", err)

	}
	authHeader(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return models.ActivityResult{}, fmt.Errorf("sendgrid: calling GET /v3/access_settings/activity: %w", err)

	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden {

		return models.ActivityResult{

			Quality: models.ActivityUnavailable,
			Source: "access_settings.activity.read scope denied on this credential",

		}, nil

	}
	if resp.StatusCode != http.StatusOK {

		return models.ActivityResult{}, fmt.Errorf("sendgrid: unexpected status %d calling GET /v3/access_settings/activity", resp.StatusCode)

	}

	var out struct {

		Result []struct {

			LastAt int64 `json:"last_at"`

		} `json:"result"`

	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {

		return models.ActivityResult{},
		fmt.Errorf("sendgrid: decoding response: %w", err)

	}
	if len(out.Result) == 0 {

		return models.ActivityResult{

			Quality: models.ActivityInferred,
			Source: "GET /v3/access_settings/activity returned no recent access attempts",

		}, nil

	}

	lastUsed := time.Unix(out.Result[0].LastAt, 0)
	return models.ActivityResult{

		LastUsedAt: &lastUsed,
		Quality: models.ActivityInferred,
		Source: "GET /v3/access_settings/activity (account-level, most recent access attempt by any method)",

	}, nil

}

//buildAuthHeader returns a function that sets the correct auth header on req,
//matching cred's subtype. Re-fetches the actual credential value fresh via
//secret.go each time. Never reads it from Metadata
func buildAuthHeader(cred models.Credential) (func(req *http.Request), error) {

	switch cred.Subtype {

	case subtypeAPIKey:
		value, err := resolveSendGridAPIKey(cred)
		if err != nil {

			return nil, err

		}
		return func(req *http.Request) {

			req.Header.Set("Authorization", "Bearer "+value)

		}, nil
	case subtypeLegacyCredentials:
		username, password, err := resolveSendGridLegacyCredentials(cred)
		if err != nil {

			return nil, err

		}
		return func(req *http.Request) {

			req.SetBasicAuth(username, password)

		}, nil
	default:
		return nil,
		fmt.Errorf("sendgrid: unrecognized credential subtype %q", cred.Subtype)

	}

}