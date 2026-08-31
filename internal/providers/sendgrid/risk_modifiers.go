package sendgrid

import (

	"context"  //carries cancellation/deadline signals through function calls
	"strings"  //string manipulation (trimming, joining scopes into one string)

	"github.com/southwickio/deadkey/internal/models"

)

//Stable RiskModifier codes for this provider. Per risk.go's doc comment, these
//must never be renamed once shipped
const (

	modifierCodeBroadScope = "sendgrid_broad_scope"
	modifierCodeLegacyCreds = "sendgrid_legacy_credentials"
	modifierCodeFullAccessLike = "sendgrid_full_access_like"
	modifierCodeNoMFAInferred = "sendgrid_no_mfa_inferred"

)

//Scopes treated as broad/high-risk. Chosen from SendGrid's own documented
//"Admin permissions" scope list: billing (financial risk), teammates and
//api_keys management (account-takeover-adjacent), and
//user.multifactor_authentication management (an attacker with this scope could
//disable a victim's MFA)
var broadScopes = map[string]string{

	"billing.update": "can modify billing and payment information",
	"teammates.create": "can create new teammate accounts",
	"teammates.delete": "can remove teammate accounts",
	"api_keys.create": "can create new API keys",
	"api_keys.delete": "can delete API keys",
	"user.multifactor_authentication.delete": "can disable a user's multi-factor authentication",

}

//RiskModifiers implements the optional providers.RiskModifierProvider
//interface. All checks are derived from data already gathered during Validate
//(scopes captured via GET /v3/scopes). No additional API call required
//Checks:
//  1. Broad/admin-adjacent scopes present (see broadScopes above)
//  2. Legacy username/password credentials, flagged simply for being that
//     credential type. SendGrid's own hardening guidance explicitly calls out
//     accounts still using passwords rather than SSO/API keys as a standing
//     risk, independent of what scopes are involved (a legacy credential has no
//     scope concept at all. It IS the full parent account)
//  3. A key holding enough of the admin scope set to be effectively
//     Full-Access-equivalent, even if not literally created as a "Full Access"
//     key in the UI. It is inferred from scope breadth, since the
//     GET /v3/scopes response does not distinguish "created as Full Access"
//     from "created as Restricted but granted every scope"
//No confirmed API exists to directly read whether MFA is enabled on the account
//(see stripe.go and github.go for the equivalent situations on those
//providers). SendGrid's own documentation states that once two-factor
//authentication is enabled, SendGrid stops accepting Basic Authentication for
//API calls entirely. This means a successful subtypeLegacyCredentials
//validation is itself indirect evidence that MFA is NOT enabled on tha
// account. This is surfaced as a modifier only for that subtype, since it has
//no meaning for API key credentials
func (p *Provider) RiskModifiers(ctx context.Context, 
	cred models.Credential) ([]models.RiskModifier, error) {

	var modifiers []models.RiskModifier

	if cred.Subtype == subtypeLegacyCredentials {

		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeLegacyCreds,
			Adjustment: 20,
			Reason: "legacy username/password credential, not scoped, full parent-account access",
			Confidence: 1.0,

		})

		//A successful Basic Auth validation (already established by the time
		//RiskModifiers runs, since deadkey only evaluates discovered
		//credentials that validated) is possible only if MFA is off, per
		//SendGrid's own documented behavior
		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeNoMFAInferred,
			Adjustment: 15,
			Reason: "account accepted Basic Authentication, which SendGrid disables once two-factor authentication is enabled - inferred MFA is not enabled",
			Confidence: 0.7,

		})
		return modifiers, nil

	}

	scopesRaw := cred.Metadata[metaScopes]
	if scopesRaw == "" {

		return modifiers, nil

	}
	grantedScopes := make(map[string]bool)
	for _, s := range strings.Split(scopesRaw, ",") {

		grantedScopes[strings.TrimSpace(s)] = true

	}

	broadCount := 0
	for scope, description := range broadScopes {

		if grantedScopes[scope] {

			broadCount++
			modifiers = append(modifiers, models.RiskModifier{

				Code: modifierCodeBroadScope,
				Adjustment: 20,
				Reason: "key has the '" + scope + "' scope: " + description,
				Confidence: 1.0,

			})

		}

	}

	//A rough heuristic for "effectively full access": holding a majority of the
	//checked admin-adjacent scopes. Not a precise measure. A true Full Access
	//key holds ~200 scopes total, far more than this small checked set. But a
	//key holding most of THESE specific high-consequence scopes is worth
	//flagging distinctly from a key holding just one
	if broadCount >= len(broadScopes)/2 && broadCount > 1 {

		modifiers = append(modifiers, models.RiskModifier{

			Code: modifierCodeFullAccessLike,
			Adjustment: 15,
			Reason: "key holds a majority of checked admin-adjacent scopes, effectively broad access regardless of how it was originally created",
			Confidence: 0.6,

		})

	}

	return modifiers, nil

}