package github

import (

	"context"  //carries cancellation/deadline signals through function calls
	"fmt"  //building error messages
	"net/http"  //making the live check request
	"strings"  //shape-checking the token's prefix
	"time"  //stamping the check time

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"

)

//ManualFieldSets implements providers.ManualEntryProvider. GitHub has one
//credential shape for manual entry purposes: a single token (classic or
//fine-grained. Both are one opaque string, distinguished later by prefix, same
//as discovery.go's classifyTokenKind)
func (p *Provider) ManualFieldSets() []providers.ManualFieldSet {

	return []providers.ManualFieldSet{

		{

			Subtype: subtypePersonalAccessToken,
			Label:   "GitHub Personal Access Token",
			Fields: []providers.ManualField{

				{Key: "token", Label: "Token", Secret: true},

			},

		},

	}

}

//BuildCredential does not confirm the token is real (that's ValidateManual's
//job); only that it has the general shape of a real GitHub token (starts with a
//recognized prefix). The returned Credential never carries the token itself
func (p *Provider) BuildCredential(subtype models.CredentialSubtype, values map[string]string) (models.Credential, error) {

	if subtype != subtypePersonalAccessToken {

		return models.Credential{}, fmt.Errorf("github: unrecognized manual entry subtype %q", subtype)

	}

	token := values["token"]
	if !strings.HasPrefix(token, "ghp_") && !strings.HasPrefix(token, "github_pat_") && !strings.HasPrefix(token, "gho_") {

		return models.Credential{}, fmt.Errorf("github: token doesn't match any recognized GitHub token prefix (ghp_, github_pat_, gho_)")

	}

	return models.Credential{

		Provider:            "github",
		Subtype:             subtypePersonalAccessToken,
		Location:            "manually added",
		DiscoveryConfidence: models.DiscoveryManual,

	}, nil

}

//ValidateManual runs the same GET /user check Validate uses for a discovered
//token, directly against the raw value. No Credential/Metadata involved. Reuses
//classifyNon200 (validate.go) for the 403/429 case, since that classification
//logic is identical regardless of where the token came from
func (p *Provider) ValidateManual(ctx context.Context, subtype models.CredentialSubtype, values map[string]string) (models.ValidationResult, error) {

	if subtype != subtypePersonalAccessToken {

		return models.ValidationResult{}, fmt.Errorf("github: unrecognized manual entry subtype %q", subtype)

	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("github: building request: %w", err)

	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+values["token"])

	resp, err := http.DefaultClient.Do(req)
	if err != nil {

		return models.ValidationResult{}, fmt.Errorf("github: calling GET /user: %w", err)

	}
	defer resp.Body.Close()

	checkedAt := time.Now()

	switch resp.StatusCode {

	case http.StatusOK:
		return models.ValidationResult{Status: models.ValidationValid, CheckedAt: checkedAt}, nil
	case http.StatusUnauthorized:
		return models.ValidationResult{Status: models.ValidationInvalid, CheckedAt: checkedAt, ErrorDetail: "HTTP 401: bad credentials"}, nil
	case http.StatusForbidden, http.StatusTooManyRequests:
		return classifyNon200(resp, checkedAt)
	default:
		return models.ValidationResult{}, fmt.Errorf("github: unexpected status %d calling GET /user", resp.StatusCode)

	}

}