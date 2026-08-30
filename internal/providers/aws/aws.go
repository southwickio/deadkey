//Package aws implements the deadkey Provider interface (see
//internal/providers/provider.go) for AWS IAM access keys
//
//API calls used, and the permission each requires, are documented per-method in
//this package (discovery.go, validate.go, activity.go, risk_modifiers.go).
//Summary, per the permission-tiering principle:
//  - Required for basic scanning:          none (sts:GetCallerIdentity requires no permissions)
//  - Required for last-used data:          iam:GetAccessKeyLastUsed
//  - Required for admin-policy risk check: iam:ListAttachedUserPolicies, iam:ListUserPolicies
//  - Required for MFA risk check:          iam:ListMFADevices
//
//A credential lacking permission for a deeper check does not cause an error.
//See each method's doc comment for exactly how it degrades
package aws

import (

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//Provider implements providers.Provider and providers.RiskModifierProvider for
//AWS. It holds no state of its own. Every method call is self-contained, since
//deadkey may validate many independently-discovered credentials in a single
//scan
type Provider struct{}

//New returns a ready-to-use AWS Provider
func New() *Provider {

	return &Provider{}

}

//Name returns this provider's identifier, used throughout deadkey
//(Credential.Provider, FeedbackPayload.Provider, CLI output, etc)
func (p *Provider) Name() string {

	return "aws"

}

//Capabilities reports that AWS can give a CONFIRMED last-used timestamp (or a
//confirmed "never used" fact). See
//docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html.
//IAM has tracked this centrally, per-key, since April 22, 2015.
func (p *Provider) Capabilities() providers.ProviderCapabilities {

	return providers.ProviderCapabilities{

		MaxActivityQuality: models.ActivityConfirmed,

	}
	
}