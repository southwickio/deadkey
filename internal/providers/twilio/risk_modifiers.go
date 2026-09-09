package twilio

import (

	"context"  //carries cancellation/deadline signals through function calls
	"encoding/json"  //parsing Key and Account resource responses
	"fmt"  //string formatting and building error messages
	"net/http"  //making the risk-check calls

	"github.com/southwickio/deadkey/internal/models"

)

//Stable RiskModifier codes for this provider. Per risk.go's doc comment, these
//must never be renamed once shipped
const (

	//A Main API Key is equivalent to full Account SID+Auth Token access. Nearly
	//always over-privileged for whatever it's actually used for.
	//Docs: twilio.com/docs/iam/api-keys
	modifierCodeMainKey = "twilio_main_key"

	//A Restricted key's granted permission breadth, when readable
	modifierCodeRestrictedKeyBreadth = "twilio_restricted_key_breadth"

	//The account this credential belongs to is a Trial account, which has its
	//own platform-level restrictions (generally limited to sending to verified
	//numbers) that can change how urgently a "forgotten" credential actually
	//matters. Docs: twilio.com/docs/usage/api/account
	//("type: Trial or Full if it's been upgraded")
	modifierCodeTrialAccount = "twilio_trial_account"

	//This credential is a subaccount, not the parent account. Informational:
	//lets the dashboard/telemetry distinguish subaccount findings from
	//top-level account findings. Docs: twilio.com/docs/usage/api/account
	//("owner_account_sid... The OwnerAccountSid of a parent account is its own
	//sid")
	modifierCodeSubaccount = "twilio_subaccount"

	//An Account SID+Auth Token pair that authenticates but gets 403/70051 on
	//Balance. Since Balance is not gated behind any Restricted-key permission
	//category in the first place (Restricted keys are a different credential
	//type entirely, never an Account SID+Auth Token pair) and a genuinely
	//live Account SID+Auth Token pair has full, ungated account access,
	//there is exactly one documented explanation for this combination: this
	//is a Test credential. Docs: twilio.com/docs/iam/test-credentials
	//("Requests to any other resource with test credentials return a 403
	//Forbidden status code". Balance is not in the small list of resources test
	//credentials can reach)
	modifierCodeLikelyTestCredential = "twilio_likely_test_credential"

)

//keyResource is the Key resource v1 fetch response shape. Confirmed against two
//independently generated SDKs from the same OpenAPI spec (twilio-ruby,
//twilio_elixir): sid, friendly_name, date_created, date_updated, policy, url.
//No type field exists. Key type must be inferred, not read directly
//Docs: twilio.com/docs/iam/api-keys/key-resource-v1
type keyResource struct {

	Policy *json.RawMessage `json:"policy"`

}

//accountResource is the subset of the Account resource this provider reads.
//Docs: twilio.com/docs/iam/api/account
type accountResource struct {

	OwnerAccountSid string `json:"owner_account_sid"`
	Sid             string `json:"sid"`
	Status          string `json:"status"` //active, suspended, closed
	Type            string `json:"type"`   //Trial, Full

}

//RiskModifiers implements the optional providers.RiskModifierProvider
//interface. It runs checks appropriate to cred's subtype, each independently
//degrading to "modifier simply omitted" (never an error or a crash) when the
//credential lacks permission for that specific check
//
//For an Account SID+Auth Token pair:
//  1. Test-credential detection (Free. Reuses the same Balance call Validate
//     already made, conceptually; this file re-derives it independently since
//     RiskModifiers has no side channel from Validate)
//  2. Account resource context (owner_account_sid, status, type): always
//     readable for this credential type, since it is the account credential
//
//For an API Key:
//  1. Key type inference via the policy field, then an optional Main/Standard
//     disambiguation probe (one extra call)
//  2. Restricted-key permission breadth, when the policy is readable
//  3. Account resource context. Only readable if the key turns out to be a Main
//     key (Standard and Restricted keys are documented as denied access to
//     /Accounts/{Sid}.json entirely). Degrades to "omitted" otherwise
func (p *Provider) RiskModifiers(ctx context.Context,
	cred models.Credential) ([]models.RiskModifier, error) {

	if cred.Metadata[metaAccountSID] == "" {

		//Orphaned API Key (see discovery.go/validate.go) - nothing further
		//can be checked without knowing which account it belongs to
		return nil, nil

	}

	switch cred.Subtype {

	case subtypeAuthToken:

		return riskModifiersForAuthToken(ctx, cred)

	case subtypeAPIKey:

		return riskModifiersForAPIKey(ctx, cred)

	default:

		return nil, nil

	}

}

func riskModifiersForAuthToken(ctx context.Context, 
	cred models.Credential) ([]models.RiskModifier, error) {

	var modifiers []models.RiskModifier

	accountSID := cred.Metadata[metaAccountSID]
	token, err := resolveAuthToken(cred)
	if err != nil {
		
		//credential no longer resolvable; nothing to add
		return nil, nil

	}

	host := hostForCredential(cred)

	//Re-derive the same authenticated-but-403-on-Balance signal Validate uses,
	//specifically to classify it as a likely test credential here
	balanceStatus, err := probeBalance(ctx, host, accountSID, accountSID, token)
	if err == nil && balanceStatus == http.StatusForbidden {

		modifiers = append(modifiers, models.RiskModifier{

			Code:       modifierCodeLikelyTestCredential,
			Adjustment: 0,
			Reason:     "authenticates successfully but is denied access to Balance; the only documented cause for an Account SID+Auth Token pair is that this is a Test credential, not a live one",
			Confidence: 0.9,

		})

		//Test credentials don't have a meaningful "account" in the normal sense
		//(twilio.com/docs/iam/test-credentials: "function in a completely
		//different environment... with no connection" to the live account).
		//Skip the Account resource fetch below
		return modifiers, nil

	}

	acct, err := fetchAccount(ctx, host, accountSID, accountSID, token)
	if err != nil {

		//Genuinely can't reach it right now (network, rate limit). Degrade
		//gracefully, add nothing further
		return modifiers, nil

	}
	if acct == nil {

		return modifiers, nil

	}

	modifiers = append(modifiers, accountContextModifiers(*acct)...)

	return modifiers, nil

}

func riskModifiersForAPIKey(ctx context.Context, 
	cred models.Credential) ([]models.RiskModifier, error) {

	var modifiers []models.RiskModifier

	accountSID := cred.Metadata[metaAccountSID]
	keySID := cred.Metadata[metaAPIKeySID]
	secret, err := resolveAPIKeySecret(cred)
	if err != nil {

		return nil, nil

	}

	host := hostForCredential(cred)

	key, err := fetchKey(ctx, host, accountSID, keySID, secret)
	if err != nil || key == nil {

		//Couldn't read the Key resource (permission denied, network issue).
		//Nothing further to add for key-type inference
		return modifiers, nil

	}

	if key.Policy != nil {

		//A non-null policy means this is a Restricted key. Its breadth is
		//already in hand. No extra call needed
		modifiers = append(modifiers, models.RiskModifier{

			Code:       modifierCodeRestrictedKeyBreadth,
			Adjustment: 0,
			Reason:     fmt.Sprintf("Restricted API Key with an explicit permission policy: %s", string(*key.Policy)),
			Confidence: 1.0,

		})

	} else {

		//Null policy means Main or Standard. Disambiguating costs one extra,
		//optional probe against a Main-only endpoint
		//(GET /Accounts/{Sid}.json). A Main key succeeds; a Standard key is
		//documented as denied (20003) specifically for this endpoint
		status, err := probeAccountFetch(ctx, host, accountSID, keySID, secret)
		if err == nil && status == http.StatusOK {

			modifiers = append(modifiers, models.RiskModifier{

				Code:       modifierCodeMainKey,
				Adjustment: 15,
				Reason:     "Main API Key: equivalent to full Account SID+Auth Token access, rather than a scoped Standard or Restricted key",
				Confidence: 1.0,

			})

			//Only a Main key can read the Account resource further. Fetch the
			//bonus context now that we know it will succeed
			acct, err := fetchAccount(ctx, host, accountSID, keySID, secret)
			if err == nil && acct != nil {

				modifiers = append(modifiers, accountContextModifiers(*acct)...)

			}

		}
		//If the probe fails or returns anything other than 200, this is a
		//Standard key. No modifier needed either way. Standard is Twilio's own
		//recommended baseline, not itself a risk signal

	}

	return modifiers, nil

}

//accountContextModifiers turns a fetched Account resource into informational
//RiskModifiers. Adjustment is 0 for facts that are context rather than risk in
//themselves (subaccount, trial). Reason/Confidence still carry the information
//through to the dashboard and telemetry
func accountContextModifiers(acct accountResource) []models.RiskModifier {

	var modifiers []models.RiskModifier

	if acct.OwnerAccountSid != "" && acct.OwnerAccountSid != acct.Sid {

		modifiers = append(modifiers, models.RiskModifier{

			Code:       modifierCodeSubaccount,
			Adjustment: 0,
			Reason:     "this credential belongs to a subaccount, not the parent account",
			Confidence: 1.0,

		})

	}

	if acct.Type == "Trial" {

		modifiers = append(modifiers, models.RiskModifier{

			Code:       modifierCodeTrialAccount,
			Adjustment: 0,
			Reason:     "Trial account: platform-restricted (e.g. generally limited to verified destination numbers), which may change how urgent this finding actually is",
			Confidence: 1.0,

		})

	}

	//acct.Status (suspended/closed) is intentionally not turned into a
	//RiskModifier here. It is surfaced through Validate's
	//ValidationAccountInactive status instead (see validate.go/evidence.go),
	//since it is a fact about whether the credential is checkable at all,
	//not a risk-scoring input alongside age/activity

	return modifiers

}

//probeBalance and probeAccountFetch return the raw HTTP status of their
//respective calls, so callers can key off the specific status codes documented
//for each (403 for the test-credential signal, 200 vs. 401/403 for the
//Main/Standard disambiguation) without duplicating the full request-building
//logic in validate.go
func probeBalance(ctx context.Context, 
	host, 
	accountSID, 
	username, 
	password string) (int, error) {

	url := fmt.Sprintf("https://%s/2010-04-01/Accounts/%s/Balance.json", 
	host, 
	accountSID)
	return doAuthedGET(ctx, url, username, password, nil)

}

func probeAccountFetch(ctx context.Context, 
	host, 
	accountSID, 
	username, 
	password string) (int, error) {

	url := fmt.Sprintf("https://%s/2010-04-01/Accounts/%s.json", 
	host, 
	accountSID)
	return doAuthedGET(ctx, url, username, password, nil)

}

func fetchAccount(ctx context.Context, 
	host, 
	accountSID, 
	username, 
	password string) (*accountResource, error) {

	url := fmt.Sprintf("https://%s/2010-04-01/Accounts/%s.json", 
	host, 
	accountSID)
	var acct accountResource
	status, err := doAuthedGET(ctx, url, username, password, &acct)
	if err != nil {

		return nil, err

	}
	if status != http.StatusOK {

		return nil, nil //not an error - just not readable with this credential

	}
	return &acct, nil

}

func fetchKey(ctx context.Context, 
	host, 
	accountSID, 
	keySID, 
	secret string) (*keyResource, error) {

	url := fmt.Sprintf("https://%s/2010-04-01/Accounts/%s/Keys/%s.json", 
	host, 
	accountSID, 
	keySID)
	var key keyResource
	status, err := doAuthedGET(ctx, url, keySID, secret, &key)
	if err != nil {

		return nil, err

	}
	if status != http.StatusOK {

		return nil, nil

	}
	return &key, nil

}

//doAuthedGET is a small shared helper for the optional, best-effort
//RiskModifier probes in this file. Unlike Validate's own request handling, a
//failure here is never surfaced as a Go error to the caller's caller. Every
//call site above treats a non-nil error or non-200 status as "this check
//simply isn't available", per the permission-tiering principle
func doAuthedGET(ctx context.Context, 
	url, username, password string, out interface{}) (int, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {

		return 0, err

	}
	req.SetBasicAuth(username, password)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return 0, err

	}
	defer resp.Body.Close()

	if out != nil && resp.StatusCode == http.StatusOK {

		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {

			return resp.StatusCode, err

		}

	}

	return resp.StatusCode, nil

}