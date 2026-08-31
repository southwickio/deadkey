package stripe

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //string formatting and building error messages
	"io"  //reading raw response bodies
	"net/http"  //making HTTP requests to Stripe's API
	"net/url"  //building the form-encoded request body for POST /v1/tokens
	"strings"  //string manipulation (trimming, building the request body reader)
	"time"  //recording when the check happened

	"github.com/southwickio/deadkey/internal/models"

)

//Validate checks whether cred is alive. Behavior differs by subtype, since
//Stripe's five credential types are not all "API keys" in the same sense. See
//stripe.go's package doc comment
//
//Secret, restricted, and organization keys: calls GET /v1/balance. Confirmed
//real and documented (docs.stripe.com/api/balance/balance_retrieve). Works for
//any authenticated key type, requires HTTP Basic Auth with the key as the
//username and an empty password (docs.stripe.com/api/authentication), NOT a
//Bearer token
//
//Publishable keys: calls POST /v1/tokens to create a minimal account token.
//Confirmed real and documented (docs.stripe.com/api/tokens/create_account).
//In test mode, this same endpoint also accepts a secret key, so a successful
//response alone does not distinguish live-mode-only pk_ behavior. What matters
//for validation purposes is simply whether the call succeeds or is rejected as
//unauthenticated
//
//Webhook secrets and Connect client IDs: neither has a documented API call
//that confirms liveness:
//  - A webhook secret (whsec_) is a local HMAC signing key, never sent to
//    Stripe at all. It has no "liveness" to check via API, by design
//  - A Connect client ID (ca_) is a public identifier for an OAuth app
//    registration, not a bearer credential. There is no per-client-ID liveness
//    check
//For these two subtypes, Validate returns a Go error explaining the
//limitation, rather than fabricating a ValidationValid/Invalid verdict it
//cannot actually support. This is a real, confirmed limitation of Stripe's API
//surface, not a gap in this implementation. See provider-requirements.md
func (p *Provider) Validate(ctx context.Context, 
	cred models.Credential) (models.ValidationResult, error) {

	value, ok := cred.Metadata[metaValue]
	if !ok || value == "" {

		return models.ValidationResult{}, 
		fmt.Errorf("credential missing %s in Metadata", metaValue)

	}

	switch cred.Subtype {

	case subtypeSecretKey, subtypeRestrictedKey, subtypeOrganizationKey:
		return validateViaBalance(ctx, value)
	case subtypePublishableKey:
		return validateViaAccountToken(ctx, value)
	case subtypeWebhookSecret:
		return models.ValidationResult{}, fmt.Errorf("stripe: webhook secrets are never sent to Stripe and have no liveness check (see validate.go)")
	case subtypeConnectClientID:
		return models.ValidationResult{}, fmt.Errorf("stripe: Connect client IDs are public identifiers with no per-ID liveness check (see validate.go)")
	default:
		return models.ValidationResult{}, fmt.Errorf("stripe: unrecognized credential subtype %q", cred.Subtype)

	}

}

func validateViaBalance(ctx context.Context, 
	secretOrRestrictedKey string) (models.ValidationResult, error) {

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.stripe.com/v1/balance", nil)
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("stripe: building request: %w", err)

	}
	//HTTP Basic Auth: the key as username, empty password. Confirmed per
	//docs.stripe.com/api/authentication. Deliberately not a Bearer token
	req.SetBasicAuth(secretOrRestrictedKey, "")

	resp, err := http.DefaultClient.Do(req)
	checkedAt := time.Now()
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("stripe: calling GET /v1/balance: %w", err)

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
		//Includes 403 (a restricted key correctly denying balance access due to
		//its own scoping. This proves the key IS alive, just insufficiently
		//permissioned for this specific call. Treating it as ValidationInvalid
		//would be wrong, since the key works fine for whatever it IS
		//permissioned for). Per the permission-tiering principle of this
		//project, a permissions-based 403 here is ambiguous evidence, not a
		//confirmed-dead signal. It is reported as an error, not silently
		//guessed either way
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{}, fmt.Errorf("stripe: unexpected status %d calling GET /v1/balance: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

}

//validateViaAccountToken calls POST /v1/tokens with a minimal, valid account
//payload, using pubKey as the Basic Auth credential. This is a real API call,
//not a read-only check the way GET /v1/balance is. It does create a
//short-lived, single-use token object in the caller's Stripe account as a
//side effect. This is a deliberate tradeoff: it is the only confirmed way to
//validate a publishable key's liveness via the REST API, and Stripe account
//tokens are inert (they do not represent money movement, customers, or
//charges; docs.stripe.com/api/tokens/create_account) so the side effect is
//minimal, but it is not zero-side-effect the way the other validation calls
//in this provider are. Worth documenting plainly rather than glossing over
func validateViaAccountToken(ctx context.Context, 
	publishableKey string) (models.ValidationResult, error) {

	form := url.Values{}
	form.Set("account[business_type]", "individual")
	form.Set("account[tos_shown_and_accepted]", "true")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.stripe.com/v1/tokens", strings.NewReader(form.Encode()))
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("stripe: building request: %w", err)

	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(publishableKey, "")

	resp, err := http.DefaultClient.Do(req)
	checkedAt := time.Now()
	if err != nil {

		return models.ValidationResult{}, 
		fmt.Errorf("stripe: calling POST /v1/tokens: %w", err)

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
		//A 400 here could mean the key is fine but this specific payload shape
		//was rejected, not that the key is dead. Same ambiguous-evidence
		//reasoning as GET /v1/balance's 403 case above. Reported as an error
		//rather than guessed either way
		body, _ := io.ReadAll(resp.Body)
		return models.ValidationResult{}, fmt.Errorf("stripe: unexpected status %d calling POST /v1/tokens: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	}

}