//Package stripe implements the deadkey Provider interface (see
//internal/providers/provider.go) for Stripe API credentials
//
//Stripe has a richer credential taxonomy than AWS or GitHub: five distinct
//types, each split live/test; documented per-type in discovery.go and
//validate.go. Summary, per the permission-tiering principle of this project:
//  - Required for basic scanning: none (reads local files/env vars, no API
//    call)
//  - Required for basic validation (secret/restricted/org keys): none beyond
//	  holding the key (GET /v1/balance)
//  - Required for basic validation (publishable keys): none beyond holding the
//	  key (POST /v1/tokens, creating a minimal account token). This call has a
//    real side effect (creates a short-lived, inert token object in the
//    account) unlike every other validation call in this project, which are all
//    read-only
//  - Required for basic validation (webhook secrets, Connect client IDs): not
//	  applicable. These two credential types have no API call that confirms
//	  liveness; see validate.go for exactly how each degrades
//  - Required for last-used data: unavailable for all credential types.
//    Stripe's Activity Logs API tracks key management events
//	  (created/deleted/updated/viewed), not key usage events. There is no
//	  API-based signal, direct or inferred, for "was this key used recently."
//    See activity.go
//  - Required for team-account risk checks: real, implemented (see scim.go),
//	  but requires an Enterprise Stripe plan with SSO enabled and SCIM
//    provisioning turned on. Set DEADKEY_STRIPE_SCIM_BEARER_TOKEN to
//	  enable. Gracefully returns no signal if unset or if the call fails. SCIM's
//    standard schema exposes account active/inactive status, not 2FA status.
//    There is no confirmed Stripe API for 2FA status at all, via SCIM or
//    otherwise
//A credential lacking an applicable check does not cause an error. See each
//method's doc comment for exactly how it degrades
package stripe

import (

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//Provider implements providers.Provider and providers.RiskModifierProvider for
//Stripe. Holds no state of its own
type Provider struct{}

//New returns a ready-to-use Stripe Provider
func New() *Provider {

	return &Provider{}

}

//Name returns this provider's identifier
func (p *Provider) Name() string {

	return "stripe"

}

//Capabilities reports Unavailable as the ceiling. Unlike GitHub, there is no
//Mode 2-style upgrade path currently implemented that could ever reach
//Confirmed. See the package doc comment above
func (p *Provider) Capabilities() providers.ProviderCapabilities {

	return providers.ProviderCapabilities{

		MaxActivityQuality: models.ActivityUnavailable,

	}

}