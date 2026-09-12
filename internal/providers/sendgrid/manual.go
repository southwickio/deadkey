package sendgrid

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //building error messages
	"net/http"  //making the live check request
	"strings"  //shape-checking the API key's prefix
	"time"  //stamping the check time

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//ManualFieldSets implements providers.ManualEntryProvider. SendGrid has two
//credential shapes, matching discovery.go's two subtypes: a modern API key (one
//field), and the legacy username/password pair (two fields); presented as
//separate selectable sets, since they need different input entirely, not just
//different validation
func (p *Provider) ManualFieldSets() []providers.ManualFieldSet {

	return []providers.ManualFieldSet{

		{

			Subtype: subtypeAPIKey,
			Label:   "API Key",
			Fields: []providers.ManualField{

				{Key: "api_key", Label: "API Key", Secret: true},

			},

		},
		{

			Subtype: subtypeLegacyCredentials,
			Label:   "Legacy Username/Password",
			Fields: []providers.ManualField{

				{Key: "username", Label: "Username", Secret: false},
				{Key: "password", Label: "Password", Secret: true},

			},

		},

	}

}

//BuildCredential confirms an API key's "SG." prefix (the one shape check
//discovery.go itself relies on, rather than character length, since real-world
//reports disagree on exact key length). Legacy credentials have no distinctive
//shape to check beyond non-empty. Neither returned Credential ever carries the
//secret/password itself
func (p *Provider) BuildCredential(subtype models.CredentialSubtype, values map[string]string) (models.Credential, error) {

	switch subtype {

	case subtypeAPIKey:

		if !strings.HasPrefix(values["api_key"], "SG.") {

			return models.Credential{}, fmt.Errorf("sendgrid: API key doesn't start with the expected \"SG.\" prefix")

		}
		return models.Credential{

			Provider:            "sendgrid",
			Subtype:             subtypeAPIKey,
			Location:            "manually added",
			DiscoveryConfidence: models.DiscoveryManual,

		}, nil

	case subtypeLegacyCredentials:

		if values["username"] == "" || values["password"] == "" {

			return models.Credential{}, fmt.Errorf("sendgrid: username and password are both required")

		}
		return models.Credential{

			Provider:            "sendgrid",
			Subtype:             subtypeLegacyCredentials,
			Location:            "manually added",
			DiscoveryConfidence: models.DiscoveryManual,
			Identifier:          values["username"],

		}, nil

	default:
		return models.Credential{}, fmt.Errorf("sendgrid: unrecognized manual entry subtype %q", subtype)

	}

}

//ValidateManual runs the same GET /v3/scopes check Validate uses, directly
//against the raw values; API key via Bearer auth, legacy credentials via Basic
//Auth, matching validate.go's two paths exactly. Reuses classify401
//(validate.go) for the 401 case
func (p *Provider) ValidateManual(ctx context.Context, subtype models.CredentialSubtype, values map[string]string) (models.ValidationResult, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.sendgrid.com/v3/scopes", nil)
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("sendgrid: building request: %w", err)

	}

	switch subtype {

	case subtypeAPIKey:
		req.Header.Set("Authorization", "Bearer "+values["api_key"])
	case subtypeLegacyCredentials:
		req.SetBasicAuth(values["username"], values["password"])
	default:
		return models.ValidationResult{}, fmt.Errorf("sendgrid: unrecognized manual entry subtype %q", subtype)

	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("sendgrid: calling GET /v3/scopes: %w", err)

	}
	defer resp.Body.Close()

	checkedAt := time.Now()

	switch resp.StatusCode {

	case http.StatusOK:
		return models.ValidationResult{Status: models.ValidationValid, CheckedAt: checkedAt}, nil
	case http.StatusUnauthorized:
		return classify401(resp, checkedAt)
	default:
		return models.ValidationResult{}, fmt.Errorf("sendgrid: unexpected status %d calling GET /v3/scopes", resp.StatusCode)

	}

}