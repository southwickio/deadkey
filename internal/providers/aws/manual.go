package aws

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //building error messages
	"strings"  //shape-checking the access key ID's prefix

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//ManualFieldSets implements providers.ManualEntryProvider. AWS has exactly one
//credential shape: an access key ID + secret access key pair. So this returns a
//single ManualFieldSet, unlike providers with more than one real credential
//shape (Twilio, SendGrid, Stripe)
func (p *Provider) ManualFieldSets() []providers.ManualFieldSet {

	return []providers.ManualFieldSet{

		{

			Subtype: subtypeAccessKey,
			Label:   "AWS Access Key",
			Fields: []providers.ManualField{

				{Key: "access_key_id", Label: "Access Key ID", Secret: false},
				{Key: "secret_access_key", Label: "Secret Access Key", Secret: true},

			},

		},

	}

}

//BuildCredential validates the access key ID's shape (confirmed prefix, per
//AWS's own documented format: "AKIA" for long-term keys, "ASIA" for
//temporary/STS-issued ones) before ever attempting a live call. Not a full
//validity check. The returned Credential never carries the secret access key
//anywhere. See ValidateManual for the live check, and
//providers.ManualEntryProvider's doc comment for the consequence of that
//constraint
func (p *Provider) BuildCredential(subtype models.CredentialSubtype, values map[string]string) (models.Credential, error) {

	if subtype != subtypeAccessKey {

		return models.Credential{}, fmt.Errorf("aws: unrecognized manual entry subtype %q", subtype)

	}

	accessKeyID := values["access_key_id"]
	if err := validateAccessKeyIDShape(accessKeyID); err != nil {

		return models.Credential{}, err

	}
	if values["secret_access_key"] == "" {

		return models.Credential{}, fmt.Errorf("aws: secret access key cannot be empty")

	}

	return models.Credential{

		Provider:            "aws",
		Subtype:             subtypeAccessKey,
		Location:            "manually added",
		DiscoveryConfidence: models.DiscoveryManual,
		Identifier:          accessKeyID,
		Metadata: map[string]string{

			metaAccessKeyID: accessKeyID,

		},

	}, nil

}

//ValidateManual builds an STS client directly from the raw values (via
//stsClientForValues. See validate.go) and runs the exact same
//sts:GetCallerIdentity check and classification (validateWithClient) that
//Validate uses for a discovered credential. No Credential or Metadata is
//involved anywhere in this path
func (p *Provider) ValidateManual(ctx context.Context, subtype models.CredentialSubtype, values map[string]string) (models.ValidationResult, error) {

	if subtype != subtypeAccessKey {

		return models.ValidationResult{}, fmt.Errorf("aws: unrecognized manual entry subtype %q", subtype)

	}

	client, err := stsClientForValues(ctx, values["access_key_id"], values["secret_access_key"])
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("aws: building STS client: %w", err)

	}

	return validateWithClient(ctx, client)

}

func validateAccessKeyIDShape(accessKeyID string) error {

	if !strings.HasPrefix(accessKeyID, "AKIA") && !strings.HasPrefix(accessKeyID, "ASIA") {

		return fmt.Errorf("aws: access key ID doesn't match AWS's documented format (expected to start with AKIA or ASIA)")

	}
	return nil

}