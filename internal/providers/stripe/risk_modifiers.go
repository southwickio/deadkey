package stripe

import (

	"context"  //carries cancellation/deadline signals through function calls

	"github.com/southwickio/deadkey/internal/models"

)

//Stable RiskModifier codes for this provider. Per risk.go's doc comment, these
//must never be renamed once shipped
const (

	modifierCodeLiveMode = "stripe_live_mode"
	modifierCodeUnrestricted = "stripe_unrestricted_key"
	modifierCodeOrganization = "stripe_organization_key"

)

//RiskModifiers implements the optional providers.RiskModifierProvider
//interface. All three checks are derived entirely from the credential's own
//value (already available from discovery/Metadata). No additional API call
//required, since Stripe encodes this information directly in the credential's
//prefix rather than requiring a lookup
//
//Stripe's design means these checks can never be permission-gated or fail due
//to insufficient access; a real, confirmed difference, not an oversight
//
//Checks:
//  1. Live mode: a _live_ credential is meaningfully higher-risk than a _test_
//     one, since it can affect real money and real customer data
//  2. Unrestricted secret key: a full sk_ (or sk_org_) key can do anything in
//     the account. A rk_ (restricted) key is inherently lower-risk by design,
//     since its permissions were deliberately scoped down at creation. This
//     provider cannot enumerate what a restricted key IS restricted to. No
//     confirmed API exposes a key's granted permissions, only the Dashboard UI
//     does (see provider-requirements.md). So this check can only flag "this
//     key has no restrictions at all," not grade a restricted key's specific
//     scope
//  3. Organization key: sk_org_ keys span multiple Stripe accounts, making
//     them higher-blast-radius than a single-account sk_ key
func (p *Provider) RiskModifiers(ctx context.Context, 
	cred models.Credential) ([]models.RiskModifier, error) {

	value, ok := cred.Metadata[metaValue]
	if !ok || value == "" {

		return nil, nil

	}

	var modifiers []models.RiskModifier

	if isLiveMode(value) {

		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeLiveMode,
			Adjustment: 20,
			Reason: "live-mode credential, affects real money and real customer data",
			Confidence: 1.0,

		})

	}

	if cred.Subtype == subtypeSecretKey {

		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeUnrestricted,
			Adjustment: 25,
			Reason: "unrestricted secret key with full account access (Stripe recommends restricted keys instead)",
			Confidence: 1.0,

		})

	}

	if cred.Subtype == subtypeOrganizationKey {

		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeOrganization,
			Adjustment: 30,
			Reason: "organization-level key with access spanning multiple Stripe accounts",
			Confidence: 1.0,

		})

	}

	//Optional, only runs if DEADKEY_STRIPE_SCIM_BEARER_TOKEN is set. See
	//scim.go. Gracefully returns nothing if not configured or if the call fails
	//for any reason
	modifiers = append(modifiers, checkSCIMTeamStatus(ctx)...)

	return modifiers, nil

}