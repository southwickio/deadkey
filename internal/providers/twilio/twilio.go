//Package twilio implements the deadkey Provider interface (see
//internal/providers/provider.go) for Twilio credentials: Account SID/Auth Token
//pairs and API Keys (Main, Standard, and Restricted)
//
//API calls used, and the permission each requires, are documented per-method
//in this package (discovery.go, validate.go, activity.go, risk_modifiers.go).
//Summary, per the permission-tiering principle:
//  - Required for basic scanning: none (local file/env reads only)
//  - Required for basic validation: none (GET .../Balance.json is reachable by
//    an Account SID+Auth Token pair, a Main key, and a Standard key; a
//    Restricted key will correctly get a 403, since Balance is not a grantable
//    Restricted-key permission at all. See validate.go)
//  - Required for subaccount/account-type context: an Account SID+Auth Token
//    pair or a Main key (GET /Accounts/{Sid}.json is denied to Standard and
//    Restricted keys)
//  - Required for key-type/permission-breadth risk check: none beyond the base
//    credential (the Key resource's own `policy` field is read as part of the
//    same permission tier as validation; disambiguating Main from Standard
//    costs one additional probe call. See risk_modifiers.go)
//
//A credential lacking permission for a deeper check does not cause an error.
//See each method's doc comment for exactly how it degrades
//
//Twilio exposes no per-credential last-used data anywhere in its API, at any
//tier, for either Auth Tokens or API Keys. See activity.go
package twilio

import (

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//Provider implements providers.Provider and providers.RiskModifierProvider for
//Twilio. It holds no state of its own. Every method call is self-contained,
//since deadkey may validate many independently-discovered credentials in a
//single scan
type Provider struct{}

//New returns a ready-to-use Twilio Provider
func New() *Provider {

	return &Provider{}

}

//Name returns this provider's identifier, used throughout deadkey
//(Credential.Provider, FeedbackPayload.Provider, CLI output, etc)
func (p *Provider) Name() string {

	return "twilio"

}

//Capabilities reports that Twilio cannot give a confirmed (or even reliably
//inferred, per-credential) last-used timestamp for any credential type. See
//activity.go for the full research trail behind this conclusion
func (p *Provider) Capabilities() providers.ProviderCapabilities {

	return providers.ProviderCapabilities{

		MaxActivityQuality: models.ActivityUnavailable,

	}

}