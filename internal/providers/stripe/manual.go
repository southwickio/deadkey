package stripe

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //building error messages

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//ManualFieldSets implements providers.ManualEntryProvider. Stripe has six
//distinct credential shapes (see discovery.go), each a single opaque value
//distinguished only by its prefix. So every field set here has exactly one
//field, and BuildCredential's real job is confirming the value actually matches
//the shape the person said they were entering
func (p *Provider) ManualFieldSets() []providers.ManualFieldSet {

	labels := map[models.CredentialSubtype]string{

		subtypeSecretKey:       "Secret Key",
		subtypeRestrictedKey:   "Restricted Key",
		subtypePublishableKey:  "Publishable Key",
		subtypeOrganizationKey: "Organization Key",
		subtypeWebhookSecret:   "Webhook Secret",
		subtypeConnectClientID: "Connect Client ID",

	}

	subtypes := []models.CredentialSubtype{

		subtypeSecretKey, subtypeRestrictedKey, subtypePublishableKey,
		subtypeOrganizationKey, subtypeWebhookSecret, subtypeConnectClientID,

	}

	sets := make([]providers.ManualFieldSet, 0, len(subtypes))
	for _, st := range subtypes {

		//Webhook secrets and Connect client IDs are not conventionally "secret"
		//in the masked-input sense the way an API key is. A webhook secret is a
		//local HMAC signing key (still sensitive, so still masked) and a
		//Connect client ID is a public identifier (not masked at all, matching
		//how Stripe itself displays it)
		secret := st != subtypeConnectClientID

		sets = append(sets, providers.ManualFieldSet{

			Subtype: st,
			Label:   labels[st],
			Fields:  []providers.ManualField{{Key: "value", Label: labels[st], Secret: secret}},

		})

	}

	return sets

}

//BuildCredential confirms the entered value's prefix actually matches the
//subtype the person selected, reusing discovery.go's own
//classifyStripeCredential rather than duplicating the prefix list a second
//time. A mismatch (for example: picking "Secret Key" but pasting a pk_ value)
//is rejected here, before any live call
func (p *Provider) BuildCredential(subtype models.CredentialSubtype, values map[string]string) (models.Credential, error) {

	value := values["value"]

	detected, ok := classifyStripeCredential(value)
	if !ok {

		return models.Credential{}, fmt.Errorf("stripe: value doesn't match any recognized Stripe credential prefix")

	}
	if detected != subtype {

		return models.Credential{}, fmt.Errorf("stripe: value looks like a %s, not a %s - check you selected the right type", detected, subtype)

	}

	return models.Credential{

		Provider:            "stripe",
		Subtype:             subtype,
		Location:            "manually added",
		DiscoveryConfidence: models.DiscoveryManual,

	}, nil

}

//ValidateManual reuses validate.go's existing validateViaBalance and
//validateViaAccountToken directly. Both already take a raw string value rather
//than a Credential, so no refactor was needed to support this path. Webhook
//secrets and Connect client IDs have no live check at all (see validate.go's
//own doc comment on this. This is a real, confirmed limitation of Stripe's API,
//not something skipped here) and return the same explanatory error Validate
//itself would
func (p *Provider) ValidateManual(ctx context.Context, subtype models.CredentialSubtype, values map[string]string) (models.ValidationResult, error) {

	switch subtype {

	case subtypeSecretKey, subtypeRestrictedKey, subtypeOrganizationKey:
		return validateViaBalance(ctx, values["value"])
	case subtypePublishableKey:
		return validateViaAccountToken(ctx, values["value"])
	case subtypeWebhookSecret:
		return models.ValidationResult{}, fmt.Errorf("stripe: webhook secrets are never sent to Stripe and have no liveness check")
	case subtypeConnectClientID:
		return models.ValidationResult{}, fmt.Errorf("stripe: Connect client IDs are public identifiers with no per-ID liveness check")
	default:
		return models.ValidationResult{}, fmt.Errorf("stripe: unrecognized manual entry subtype %q", subtype)

	}

}