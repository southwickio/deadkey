package twilio

import (

	"context"  //carries cancellation/deadline signals through function calls
	"encoding/json"  //parsing Twilio's JSON error body
	"fmt"  //string formatting and building error messages
	"io"  //reading the HTTP response body
	"net/http"  //making the validate call
	"time"  //stamping CheckedAt

	"github.com/southwickio/deadkey/internal/models"

)

//twilioErrorBody is the shape of Twilio's documented REST API error response.
//Docs: twilio.com/docs/usage/twilios-response and every individual error page
//(e.g. twilio.com/docs/api/errors/20003) shows this exact shape: code, message,
//more_info, status. The numeric `code` field is the reliable signal this
//provider keys off of; NOT the bare HTTP status, since Twilio documents several
//unrelated causes sharing the same HTTP status (see the doc comment on
//classifyError below)
type twilioErrorBody struct {

	Code int `json:"code"`
	Message string `json:"message"`
	MoreInfo string `json:"more_info"`
	Status int `json:"status"`

}

//Twilio error codes this provider distinguishes between. Each is documented
//at twilio.com/docs/api/errors/<code>
const (

	//"Account is not active": the account is suspended or closed. Distinct from
	//a bad credential. The credential itself authenticated correctly
	errCodeAccountNotActive = 10001

	//"Permission Denied": generic auth failure. Twilio's own docs list many
	//causes sharing this one code (wrong SID/token, deleted key, wrong
	//region, a Standard/Restricted key hitting a Main-only endpoint). None of
	//which apply to the Balance endpoint used here except a genuinely wrong
	//credential, once region/hostname has been correctly targeted
	errCodePermissionDenied = 20003

	//"Authorization Failed": specifically documented as firing when a
	//Restricted API Key is missing the permission for the resource being
	//called. This is the signal that separates "authenticated but
	//permission-scoped" from "not authenticated at all"
	errCodeAuthorizationFailed = 70051

)

//defaultHost is used when no region/edge was captured at discovery time.
//Region-specific hosts follow the documented api.{edge}.{region}.twilio.com
//pattern, confirmed directly from a real twilio-cli debug log
//(get https://api.sydney.jp1.twilio.com/2010-04-01/Accounts/...). Docs:
//twilio.com/docs/global-infrastructure/understanding-twilio-regions
const defaultHost = "api.twilio.com"

//hostForCredential builds the correct hostname for cred, per Twilio's
//Regions/Edges system. Using the wrong host for a credential from a non-default
//region produces the same 401 as a genuinely invalid credential (confirmed:
//20003's own documented causes list "Attempted API Key is for the incorrect
//Twilio Region"). So this must be resolved BEFORE interpreting any error
//response, not treated as a fallback after the fact
func hostForCredential(cred models.Credential) string {

	region := cred.Metadata[metaRegion]
	edge := cred.Metadata[metaEdge]

	if region == "" || region == "us1" {

		if edge == "" {

			return defaultHost

		}

	}
	if edge != "" && region != "" {

		return fmt.Sprintf("api.%s.%s.twilio.com", edge, region)

	}
	if region != "" {

		return fmt.Sprintf("api.%s.twilio.com", region)

	}
	return defaultHost

}

//Validate calls GET .../Balance.json; the minimum-permission check for Twilio
//credentials
//
//Why not the more obvious GET /Accounts/{Sid}.json? Because Standard and
//Restricted API Keys are documented as denied access to the Accounts resource
//itself, and that denial comes back as error 20003, which is the SAME code used
//for a genuinely wrong credential. Using that endpoint would make perfectly
//live Standard/Restricted keys look dead
//
//Balance doesn't have that problem. Main keys, Standard keys, and an Account
//SID+Auth Token pair can all read it normally. Restricted keys can't, but
//that's expected. Balance isn't a grantable permission category at all
//(confirmed against Twilio's list of Restricted-key categories: Studio, Voice,
//Messaging, TaskRouter, Lookup, Verify, Video, Phone Numbers, Monitor, Event
//Streams, Usage Records, Serverless, IAM, Flex, Conversations). So a Restricted
//key predictably gets a 403 (error 70051) here; never a false success, and
//never mistaken for a dead credential
func (p *Provider) Validate(ctx context.Context,
	cred models.Credential) (models.ValidationResult, error) {

	now := time.Now()

	accountSID := cred.Metadata[metaAccountSID]
	if accountSID == "" {

		return models.ValidationResult{

			Status:    models.ValidationError,
			CheckedAt: now,
			ErrorDetail: "no Account SID found alongside this API Key at discovery time; " +
				"Twilio has no way to identify an account from an API Key alone, so this " +
				"credential cannot be validated without pairing it manually (see `deadkey add`)",

		}, nil

	}

	username, password, err := credentialForAuth(cred)
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("twilio: %w", err)

	}

	host := hostForCredential(cred)
	url := fmt.Sprintf("https://%s/2010-04-01/Accounts/%s/Balance.json", host, accountSID)

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

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {

		return models.ValidationResult{

			Status:          models.ValidationValid,
			CheckedAt:       now,
			CheckedEndpoint: host,

		}, nil

	}

	return classifyError(resp.StatusCode, body, host, now)

}

//classifyError interprets a non-200 Balance response using the JSON body's
//`code` field as the primary signal, per this file's twilioErrorBody doc
//comment. A body that fails to parse (unexpected shape, non-Twilio intermediary
//error, etc.) is treated as ValidationError - "the check failed", never guessed
//into Invalid
func classifyError(httpStatus int, body []byte, host string, checkedAt time.Time) (models.ValidationResult, error) {

	var errBody twilioErrorBody
	if err := json.Unmarshal(body, &errBody); err != nil || errBody.Code == 0 {

		return models.ValidationResult{

			Status:          models.ValidationError,
			CheckedAt:       checkedAt,
			CheckedEndpoint: host,
			ErrorDetail:     fmt.Sprintf("HTTP %d, unparseable or unrecognized Twilio error body: %s", httpStatus, string(body)),

		}, nil

	}

	switch errBody.Code {

	case errCodeAccountNotActive:

		return models.ValidationResult{

			Status:          models.ValidationAccountInactive,
			CheckedAt:       checkedAt,
			CheckedEndpoint: host,
			ErrorDetail:     errBody.Message,

		}, nil

	case errCodeAuthorizationFailed:

		//Authenticated, but this specific resource is outside the credential's
		//granted permissions (expected and normal for Restricted API Keys. See
		//this file's Validate doc comment). The credential is alive.
		//RiskModifiers may separately note the permission scope
		return models.ValidationResult{

			Status:          models.ValidationValid,
			CheckedAt:       checkedAt,
			CheckedEndpoint: host,

		}, nil

	case errCodePermissionDenied:

		if httpStatus == http.StatusForbidden {

			//Same treatment as errCodeAuthorizationFailed: some Restricted-key
			//permission failures surface as 20003/403 rather than 70051,
			//depending on which layer rejects the request. Either way, a 403
			//status means "authenticated, not authorized", never "invalid"
			return models.ValidationResult{

				Status:          models.ValidationValid,
				CheckedAt:       checkedAt,
				CheckedEndpoint: host,

			}, nil

		}

		return models.ValidationResult{

			Status:          models.ValidationInvalid,
			CheckedAt:       checkedAt,
			CheckedEndpoint: host,
			ErrorDetail:     errBody.Message,

		}, nil

	default:

		return models.ValidationResult{

			Status:      models.ValidationError,
			CheckedAt:   checkedAt,
			CheckedEndpoint: host,
			ErrorDetail: fmt.Sprintf("HTTP %d, Twilio error %d: %s", httpStatus, errBody.Code, errBody.Message),

		}, nil

	}

}

//credentialForAuth resolves the correct HTTP Basic Auth username/password pair
//for cred's subtype, re-reading the secret fresh (see secret.go)
func credentialForAuth(cred models.Credential) (username, password string, err error) {

	switch cred.Subtype {

	case subtypeAuthToken:

		token, err := resolveAuthToken(cred)
		if err != nil {

			return "", "", err

		}
		return cred.Metadata[metaAccountSID], token, nil

	case subtypeAPIKey:

		secret, err := resolveAPIKeySecret(cred)
		if err != nil {

			return "", "", err

		}
		return cred.Metadata[metaAPIKeySID], secret, nil

	default:

		return "", "", fmt.Errorf("unrecognized credential subtype %q", cred.Subtype)

	}

}