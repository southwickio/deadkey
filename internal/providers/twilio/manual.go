package twilio

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //building error messages
	"io"  //reading the response body
	"net/http"  //making the live check request
	"time"  //stamping the check time

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//ManualFieldSets implements providers.ManualEntryProvider. Twilio's two
//fundamentally different credential shapes (see discovery.go) need different
//fields: an Account SID+Auth Token pair (two fields), or an API Key, which
//itself needs the Account SID alongside it
//
//Region/Edge are not collected here. Manually-added Twilio credentials are
//validated against the default host only. A reasonable, stated simplification:
//manual entry exists for occasional/edge-case registration, not as a
//replacement for discovery's region-aware handling
func (p *Provider) ManualFieldSets() []providers.ManualFieldSet {

	return []providers.ManualFieldSet{

		{

			Subtype: subtypeAuthToken,
			Label:   "Account SID + Auth Token",
			Fields: []providers.ManualField{

				{Key: "account_sid", Label: "Account SID", Secret: false},
				{Key: "auth_token", Label: "Auth Token", Secret: true},

			},

		},
		{

			Subtype: subtypeAPIKey,
			Label:   "API Key",
			Fields: []providers.ManualField{

				{Key: "account_sid", Label: "Account SID", Secret: false},
				{Key: "api_key_sid", Label: "API Key SID", Secret: false},
				{Key: "api_key_secret", Label: "API Key Secret", Secret: true},

			},

		},

	}

}

//BuildCredential checks the Account SID/Key SID's shape (Twilio SIDs are always
//a 2-letter prefix + 32 hex characters, per discovery.go's own
//accountSIDPattern/apiKeySIDPattern) before any live call. The returned
//Credential carries the Account SID (and, for an API Key, the Key SID) in
//Metadata. Both are designed to be non-secret
func (p *Provider) BuildCredential(subtype models.CredentialSubtype, values map[string]string) (models.Credential, error) {

	accountSID := values["account_sid"]
	if !accountSIDPattern.MatchString(accountSID) {

		return models.Credential{}, fmt.Errorf("twilio: Account SID doesn't match Twilio's documented format (AC followed by 32 hex characters)")

	}

	switch subtype {

	case subtypeAuthToken:

		if values["auth_token"] == "" {

			return models.Credential{}, fmt.Errorf("twilio: Auth Token cannot be empty")

		}
		return models.Credential{

			Provider:            "twilio",
			Subtype:             subtypeAuthToken,
			Location:            "manually added",
			DiscoveryConfidence: models.DiscoveryManual,
			Identifier:          accountSID,
			Metadata:            map[string]string{metaAccountSID: accountSID},

		}, nil

	case subtypeAPIKey:

		keySID := values["api_key_sid"]
		if !apiKeySIDPattern.MatchString(keySID) {

			return models.Credential{}, fmt.Errorf("twilio: API Key SID doesn't match Twilio's documented format (SK followed by 32 hex characters)")

		}
		if values["api_key_secret"] == "" {

			return models.Credential{}, fmt.Errorf("twilio: API Key Secret cannot be empty")

		}
		return models.Credential{

			Provider:            "twilio",
			Subtype:             subtypeAPIKey,
			Location:            "manually added",
			DiscoveryConfidence: models.DiscoveryManual,
			Identifier:          keySID,
			Metadata:            map[string]string{metaAccountSID: accountSID, metaAPIKeySID: keySID},

		}, nil

	default:
		return models.Credential{}, fmt.Errorf("twilio: unrecognized manual entry subtype %q", subtype)

	}

}

//ValidateManual runs the same GET .../Balance.json check Validate uses,
//directly against the raw values, always targeting the default host (see this
//file's doc comment on why Region/Edge aren't collected manually). Reuses
//classifyError (validate.go), which already takes raw values rather than a
//Credential
func (p *Provider) ValidateManual(ctx context.Context, subtype models.CredentialSubtype, values map[string]string) (models.ValidationResult, error) {

	accountSID := values["account_sid"]

	var username, password string
	switch subtype {

	case subtypeAuthToken:
		username, password = accountSID, values["auth_token"]
	case subtypeAPIKey:
		username, password = values["api_key_sid"], values["api_key_secret"]
	default:
		return models.ValidationResult{}, fmt.Errorf("twilio: unrecognized manual entry subtype %q", subtype)

	}

	url := fmt.Sprintf("https://%s/2010-04-01/Accounts/%s/Balance.json", defaultHost, accountSID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("twilio: building request: %w", err)

	}
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("twilio: calling GET .../Balance.json: %w", err)

	}
	defer resp.Body.Close()

	checkedAt := time.Now()

	if resp.StatusCode == http.StatusOK {

		return models.ValidationResult{Status: models.ValidationValid, CheckedAt: checkedAt, CheckedEndpoint: defaultHost}, nil

	}

	body, _ := io.ReadAll(resp.Body)

	return classifyError(resp.StatusCode, body, defaultHost, checkedAt)

}