package github

import (
	"context"  //carries cancellation/deadline signals through function calls
	"os"  //reading the private key file from disk

	"github.com/southwickio/deadkey/internal/models"
)

//Environment variables a user can set to enable Mode 2 (GitHub App-backed
//activity data). Not part of the shared providers.DiscoveryConfig. Per the
//design principle in discovery_config.go, provider-specific configuration is
//added on its own, lazily, when a provider actually needs something the shared
//struct can't express. GitHub App credentials are exactly that: nothing else in
//V0 needs anything like this
//
//Documented in provider-requirements.md, not here in detail. This file states
//what's needed, provider-requirements.md and the eventual real docs point to
//GitHub's own guide for how to actually create a GitHub App
const (

	envGitHubAppID = "DEADKEY_GITHUB_APP_ID"
	envGitHubAppPrivateKeyPath = "DEADKEY_GITHUB_APP_PRIVATE_KEY_PATH"
	envGitHubAppOrg = "DEADKEY_GITHUB_APP_ORG"

)

//GetActivity reports how "alive" cred looks
//
//Mode 1 (default, no GitHub App configured): returns ActivityUnavailable.
//Confirmed via GitHub's own REST API schema that GET /user (the validation
//call) returns no token-level last-used field, and that no
//personal-access-token-scoped endpoint exposes this to the token's own holder.
//token_last_used_at exists, but only via an org-level endpoint callable by a
//GitHub App, never by the personal access token itself
//
//Mode 2 (a GitHub App is configured via the env vars above): calls GET
///orgs/{org}/personal-access-tokens as the GitHub App, which returns
//token_last_used_at for fine-grained tokens the org can see. Confirmed real and
//documented (docs.github.com/en/rest/orgs/personal-access-tokens)
//
//Mode 2 has a real limitation: it only ever applies to fine-grained tokens,
//since token_last_used_at is only exposed for tokens the org can see and
//approve. Classic tokens are invisible to org admins entirely (confirmed: 
//GitHub's own documentation states org owners cannot see members' classic
//tokens at all). A classic token will always be ActivityUnavailable, in both
//modes, and this is a structural GitHub limitation, not a gap in this
//implementation
func (p *Provider) GetActivity(ctx context.Context, 
	cred models.Credential) (models.ActivityResult, error) {

	if cred.Metadata[metaTokenKind] == "classic" {

		return models.ActivityResult{

			Quality: models.ActivityUnavailable,
			Source: "classic tokens are not visible to organization admins and have no last-used field available via any GitHub API",

		}, nil

	}

	appID := os.Getenv(envGitHubAppID)
	privateKeyPath := os.Getenv(envGitHubAppPrivateKeyPath)
	org := os.Getenv(envGitHubAppOrg)

	if appID == "" || privateKeyPath == "" || org == "" {

		return models.ActivityResult{

			Quality: models.ActivityUnavailable,
			Source: "no GitHub App configured (Mode 2) — set " + envGitHubAppID + ", " + envGitHubAppPrivateKeyPath + ", and " + envGitHubAppOrg + " to enable; see provider-requirements.md",

		}, nil

	}

	return getActivityViaGitHubApp(ctx, cred, appID, privateKeyPath, org)
	
}