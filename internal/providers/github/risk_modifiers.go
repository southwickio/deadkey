package github

import (

	"context"  //carries cancellation/deadline signals through function calls
	"strings"  //string manipulation (trimming)

	"github.com/southwickio/deadkey/internal/models"

)

//Stable RiskModifier codes for this provider. Per risk.go's doc comment, these
//must never be renamed once shipped
const (

	modifierCodeBroadScope = "github_broad_scope"
	modifierCodeClassicType = "github_classic_token"

)

//Scopes treated as broad/high-risk if granted to a classic token. Not
//exhaustive by design. These are the scopes GitHub's own documentation flags as
//the most consequential (full repo access, full org admin, destructive repo
//deletion), chosen as a defensible starting set rather than an attempt to score
//every possible scope combination
var broadScopes = map[string]string{

	"repo": "full control of private repositories",
	"admin:org": "full control of organizations and teams",
	"delete_repo": "ability to delete repositories",
	"admin:public_key": "full control of public keys",

}

//RiskModifiers implements the optional providers.RiskModifierProvider
//interface. Two checks, both derived entirely from data already gathered during
//Validate; no additional API call required:
//  1. Does a classic token carry a broad, high-consequence scope? Scopes are
//     read from Metadata (populated by Validate via the X-OAuth-Scopes response
//     header. Confirmed real and documented). Fine-grained tokens do not
//     populate this field at all (they use a different permission model), so
//     this check naturally only ever fires for classic tokens
//  2. Is this a classic token at all? GitHub's own guidance steers users toward
//     fine-grained tokens as the more secure default (mandatory expiration,
//     narrower scope, subject to org approval policies). A classic token is
//     inherently a weaker security posture regardless of its specific scopes,
//     so this is flagged as its own, smaller, independent modifier
//Both checks require nothing beyond what Validate already gathered. No
//permission gap is possible here
func (p *Provider) RiskModifiers(ctx context.Context,
	cred models.Credential) ([]models.RiskModifier, error) {

	if cred.Metadata[metaTokenKind] != "classic" {

		return nil, nil

	}

	var modifiers []models.RiskModifier

	modifiers = append(modifiers, models.RiskModifier{

		Code: modifierCodeClassicType,
		Adjustment: 10,
		Reason: "classic personal access token (GitHub recommends fine-grained tokens instead)",
		Confidence: 1.0,

	})

	scopesRaw := cred.Metadata[metaScopes]
	if scopesRaw == "" {

		return modifiers, nil

	}

	grantedScopes := make(map[string]bool)
	for _, s := range strings.Split(scopesRaw, ",") {

		grantedScopes[strings.TrimSpace(s)] = true

	}

	for scope, description := range broadScopes {

		if grantedScopes[scope] {

			modifiers = append(modifiers, models.RiskModifier{

				Code: modifierCodeBroadScope,
				Adjustment: 25,
				Reason: "token has the '" + scope + "' scope: " + description,
				Confidence: 1.0,

			})

		}

	}

	return modifiers, nil
	
}