//Package sendgrid implements the deadkey Provider interface (see
//internal/providers/provider.go) for SendGrid API credentials
//
//SendGrid has two distinct credential shapes: modern API keys (SG. prefix) and
//a legacy username/password pair still accepted for a narrow set of operations.
//Documented per-method in this package. Summary, per the permission-tiering
//principle of this project:
//  - Required for basic scanning: none (reads env vars only. No official
//    SendGrid CLI config file was found to exist, confirmed against the real
//    sendgrid/sendgrid-cli source)
//  - Required for basic validation (API keys): none beyond holding the key
//	  (GET /v3/scopes, self-referential; a key asking about its own scopes)
//  - Required for basic validation (legacy username/password): none beyond
//	  holding the credential, using HTTP Basic Auth. Less confirmed than the
//	  API key path. See validate.go
//  - Required for last-used data: none beyond holding the key
//	  (GET /v3/access_settings/activity). This is account-level access history,
//    not a per-key field. See activity.go for why this is ActivityInferred,
//    not ActivityConfirmed
//  - Required for scope-breadth risk checks: none. Derived from the scopes
//    already returned by the validation call, no extra API call
//
//A credential lacking permission for a deeper check does not cause an error.
//See each method's doc comment for exactly how it degrades
package sendgrid

import (

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//Provider implements providers.Provider and providers.RiskModifierProvider
//for SendGrid. Holds no state of its own
type Provider struct{}

//New returns a ready-to-use SendGrid Provider
func New() *Provider {

	return &Provider{}

}

//Name returns this provider's identifier
func (p *Provider) Name() string {

	return "sendgrid"

}

//Capabilities reports ActivityInferred as the ceiling. Confirmed via
//GET /v3/access_settings/activity's documented last_at field (a real Unix
//timestamp), but this is account-level access-attempt data, not a per-key usage
//field the way AWS's is; hence Inferred, not Confirmed
func (p *Provider) Capabilities() providers.ProviderCapabilities {

	return providers.ProviderCapabilities{

		MaxActivityQuality: models.ActivityInferred,

	}

}