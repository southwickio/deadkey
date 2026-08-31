package stripe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/southwickio/deadkey/internal/models"
)

// Environment variable enabling the optional SCIM-based team check. Not
// part of the shared providers.DiscoveryConfig, per the same
// add-lazily-when-needed principle used for GitHub's GitHub App config
// (see discovery_config.go and github/activity.go).
//
// This check requires an Enterprise Stripe plan with SSO enabled and SCIM
// provisioning turned on (docs.stripe.com/get-started/account/sso/scim) -
// out of reach for the large majority of deadkey users, but real and
// buildable for the ones who do have it, the same way GitHub's Mode 2 is
// built for real despite requiring a GitHub App most users won't set up.
const envStripeSCIMBearerToken = "DEADKEY_STRIPE_SCIM_BEARER_TOKEN"

// scimBaseURL per docs.stripe.com/get-started/account/sso/scim. Note: one
// source found during research referenced dashboard.stripe.com/scim/v2
// instead of access.stripe.com/scim/v2 - the official docs page uses
// access.stripe.com, used here, but this discrepancy is worth confirming
// against a real Stripe Enterprise+SSO account before relying on it in
// production, since it was not independently reconcilable during this
// research pass.
const scimBaseURL = "https://access.stripe.com/scim/v2"

// Stable RiskModifier code for this check.
const modifierCodeInactiveTeamAccount = "stripe_scim_inactive_account"

// checkSCIMTeamStatus is called from RiskModifiers when the SCIM bearer
// token env var is configured. It queries Stripe's SCIM Users endpoint
// (standard SCIM 2.0, RFC 7644) and reports whether ANY team member
// account is inactive - not a per-credential check, since a Stripe API
// credential has no inherent link to a specific team member account the
// way an AWS IAM key is tied to a specific IAM user.
//
// Honest scope limit: standard SCIM's core User schema (RFC 7643) defines
// an "active" boolean, confirmed real and universal across SCIM
// implementations. It does NOT define a two-factor-authentication status
// field - MFA/2FA is outside SCIM's core schema entirely. This check can
// therefore report "at least one team member account is deactivated but
// may still have residual access," which is a real, useful signal, but it
// is NOT an equivalent to AWS's "no MFA enrolled" check - no confirmed
// Stripe API exposes 2FA status at all, via SCIM or otherwise.
//
// If the SCIM call fails for any reason (not configured, wrong
// credentials, endpoint not enabled, network failure), this returns no
// modifier and no error - a team-level check failing must never break
// evaluation of the actual credential being scanned.
func checkSCIMTeamStatus(ctx context.Context) []models.RiskModifier {
	bearerToken := os.Getenv(envStripeSCIMBearerToken)
	if bearerToken == "" {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scimBaseURL+"/Users", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Accept", "application/scim+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var out struct {
		Resources []struct {
			UserName string `json:"userName"`
			Active   bool   `json:"active"`
		} `json:"Resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil
	}

	var inactiveUsers []string
	for _, u := range out.Resources {
		if !u.Active {
			inactiveUsers = append(inactiveUsers, u.UserName)
		}
	}
	if len(inactiveUsers) == 0 {
		return nil
	}

	return []models.RiskModifier{{
		Code:       modifierCodeInactiveTeamAccount,
		Adjustment: 15,
		Reason:     fmt.Sprintf("%d team member account(s) deactivated via SCIM but may retain residual access: %s", len(inactiveUsers), strings.Join(inactiveUsers, ", ")),
		Confidence: 0.6, // account deactivation doesn't necessarily mean THIS credential is affected - lower confidence than a direct per-credential check
	}}
}
