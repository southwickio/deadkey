//Package github implements the deadkey Provider interface (see
//internal/providers/provider.go) for GitHub personal access tokens (both
//classic and fine-grained)
//
//Discovery, validation, activity, and risk-modifier logic, and the permission
//each requires, are documented per-method in this package (discovery.go,
//validate.go, activity.go, risk_modifiers.go)
//
//Summary, per the permission-tiering principle in roadmap-v3:
//  - Required for basic scanning: none (reads local files/env vars, no API
//    call)
//  - Required for basic validation: none beyond holding the token (GET /user)
//  - Required for last-used data (Mode 1, no GitHub App): unavailable
//  - Required for last-used data (Mode 2, with a GitHub App): a GitHub App
//	  registered with org-level "Personal access tokens" (read) permission,
//	  installed and configured. See discovery of GitHub App credentials in
//	  activity.go, and provider-requirements.md for the full setup pointer.
//  - Required for scope-breadth risk check: none beyond holding a classic token
//    (scopes are returned via a response header on the same GET /user call used
//    for validation)
//
//A credential lacking permission or configuration for a deeper check does not
//cause an error. See each method's doc comment for exactly how it degrades
package github

import (

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//Provider implements providers.Provider and providers.RiskModifierProvider for
//GitHub. It holds no state of its own. Every method call is self-contained
type Provider struct{}

//New returns a ready-to-use GitHub Provider
func New() *Provider {

	return &Provider{}

}

//Name returns this provider's identifier
func (p *Provider) Name() string {

	return "github"

}

//Capabilities reports the ceiling this provider can EVER achieve, which is
//"Confirmed", but only when a GitHub App is configured (Mode 2, see
//activity.go). Without one (Mode 1, the default), GetActivity reports
//"Unavailable" per-credential. Capabilities() is a static, per-provider ceiling
//queried once (see capabilities.go in internal/providers). It intentionally
//does not know whether a GitHub App happens to be configured for any specific
//scan. GetActivity itself reports the real, honest per-credential quality every
//time it runs
func (p *Provider) Capabilities() providers.ProviderCapabilities {

	return providers.ProviderCapabilities{

		MaxActivityQuality: models.ActivityConfirmed,

	}

}