# Dead Key Finder - Provider Documentation Requirements

This is a working checklist, not the final published documentation. It tracks
what each provider's eventual docs/README section needs to contain, so
nothing gets missed once we're ready to write real user-facing documentation
or a docs site.

Format per provider:
- deadkey usage: written by us, real how-to (flags, examples, sample output)
- What deadkey checks, and what each needs: a permission-tier table
- Provider-side setup: stated clearly, linked out to the provider's own
  docs, never a tutorial we write ourselves for their platform

---

## AWS

### deadkey usage

- `deadkey scan --provider aws` - scan for AWS credentials only
- `deadkey scan --path ~/custom/.aws/credentials` - override the default
  credentials file location
- `deadkey add` -> select "AWS" -> manually register a credential
- `deadkey ignore <location>` -> stop flagging a specific credential slot
  (e.g. "the default profile key"), survives rotation

### What deadkey checks, and what each needs

| Check | Required permission | Notes |
|---|---|---|
| Discovery | none | reads ~/.aws/credentials and AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars locally, no API call |
| Basic validation | none | sts:GetCallerIdentity requires no permissions, per AWS's own documentation |
| Last-used data | iam:GetAccessKeyLastUsed | confirmed data, not inferred. AWS has tracked this since April 22, 2015 |
| Admin-policy risk check | iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:GetUserPolicy | checks both managed and inline policies by actual content, not name |
| MFA risk check | iam:ListMFADevices | flags if the user has zero enrolled devices |

### Provider-side setup

- To grant these permissions to the credential deadkey will scan with, see
  AWS's IAM policy documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
- No AWS-side toggle or app registration is required. All of the above works
  with a standard IAM user access key, provided it has the listed
  permissions.

---

## GitHub

### deadkey usage

- `deadkey scan --provider github` - scan for GitHub tokens only
- `deadkey scan --path ~/custom/hosts.yml` - override the default hosts.yml
  location checked as a legacy fallback
- `deadkey add` -> select "GitHub" -> manually register a token
- `deadkey ignore <location>` -> stop flagging a specific credential slot

Discovery checks six locations automatically, in order: GITHUB_TOKEN/GH_TOKEN
env vars, `gh auth token` (gh CLI's own resolved token, any storage backend),
~/.config/gh/hosts.yml (legacy plaintext fallback), ~/.netrc, ~/.git-credentials,
and `git credential fill` (any other configured git credential helper,
including OS keyrings and Git Credential Manager).

### What deadkey checks, and what each needs

| Check | Required permission | Notes |
|---|---|---|
| Discovery | none | reads local files/env vars or shells out to gh/git, no API call |
| Basic validation | none beyond holding the token | GET /user requires no fine-grained permissions, confirmed against the actual response schema |
| Scope-breadth risk check | none beyond holding a classic token | scopes come from the X-OAuth-Scopes response header on the same GET /user call already made for validation, no extra API call |
| Classic-token-type flag | none | derived from the token's own prefix (ghp_ vs github_pat_), no API call |

**Mode 1: No GitHub App configured (default)**

| Check | Required permission | Notes |
|---|---|---|
| Last-used data | Unavailable | no API exists that exposes this to the token's own holder |

**Mode 2: With a GitHub App configured (optional, unlocks more)**

| Check | Required permission | Notes |
|---|---|---|
| Last-used data | GitHub App with org-level "Personal access tokens" (read) permission, installed on the org | exposes token_last_used_at via GET /orgs/{org}/personal-access-tokens. Confirmed real, documented field |

### Provider-side setup

- Mode 1 requires nothing beyond having a token.
- Mode 2 requires the organization to have a registered GitHub App with
  "Personal access tokens" (read) permission installed. See GitHub's guide
  on creating a GitHub App: https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/about-creating-github-apps
- To enable Mode 2 in deadkey, set three environment variables:
  DEADKEY_GITHUB_APP_ID, DEADKEY_GITHUB_APP_PRIVATE_KEY_PATH,
  DEADKEY_GITHUB_APP_ORG.
- Organization owners can additionally require or waive approval for
  fine-grained personal access tokens under Organization Settings ->
  Personal access tokens -> Settings. This is a free, self-service toggle,
  separate from the GitHub App requirement above. See:
  https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization

### Known limitations

- Classic tokens can never get last-used data, in either mode. GitHub does
  not expose this to org admins at all for classic tokens (confirmed:
  GitHub's own documentation states org owners cannot see members' classic
  tokens). This is a structural GitHub limitation, not a gap in deadkey.
- Mode 2 is implemented (real GitHub App JWT authentication, real API call)
  but is not yet fully wired end to end: the org-level endpoint is queried
  by a token's numeric token_id, not by its raw value, and no confirmed
  GitHub API lets deadkey resolve a locally-discovered token to its
  token_id. Until this is resolved, Mode 2 will correctly report
  ActivityUnavailable with an explanation, even when properly configured.
  Tracked as a follow-up, not silently worked around with a guess.
- Inline-content-based risk scoring (parity with AWS's inline-policy check)
  does not apply here; GitHub's permission model for fine-grained tokens is
  structurally different (granular permissions, not content-based policy
  documents), so no equivalent deeper check has been identified yet.

---

## Stripe

### deadkey usage

- `deadkey scan --provider stripe` - scan for Stripe credentials only
- `deadkey scan --path ~/custom/config.toml` - override the default Stripe
  CLI config file location
- `deadkey add` -> select "Stripe" -> manually register a credential
- `deadkey ignore <location>` -> stop flagging a specific credential slot

Discovery checks two locations automatically: known env var names
(STRIPE_API_KEY, STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY,
STRIPE_WEBHOOK_SECRET, STRIPE_CONNECT_CLIENT_ID) and
~/.config/stripe/config.toml (the Stripe CLI's own config file, scanning
every named project section, not just the default).

Stripe has five distinct credential types, each identified by prefix and
tracked as a distinct subtype: secret keys (sk_), restricted keys (rk_),
publishable keys (pk_), organization keys (sk_org_), webhook secrets
(whsec_), and Connect client IDs (ca_). Each splits live/test mode except
webhook secrets and Connect client IDs.

### What deadkey checks, and what each needs

| Check | Required permission | Notes |
|---|---|---|
| Discovery | none | reads local files/env vars, no API call |
| Basic validation (secret/restricted/organization keys) | none beyond holding the key | GET /v1/balance, confirmed to work with any authenticated key. Uses HTTP Basic Auth (key as username, empty password), not a Bearer token |
| Basic validation (publishable keys) | none beyond holding the key | POST /v1/tokens (create a minimal account token). Confirmed real and documented. Unlike every other validation call in this project, this has a real side effect - it creates a short-lived, inert token object in the account |
| Basic validation (webhook secrets, Connect client IDs) | not applicable | no confirmed API exists to check liveness for these two subtypes - see Known Limitations |
| Live-mode risk flag | none | derived from the credential's own value (_live_ substring), no API call |
| Unrestricted-key risk flag | none | derived from the credential's own prefix, no API call |
| Organization-key risk flag | none | derived from the credential's own prefix, no API call |
| Team-account status risk flag (optional) | Enterprise plan with SSO + SCIM provisioning enabled | see Known Limitations for exact scope |

### Provider-side setup

- No setup is required beyond having a credential. All checks that are
  possible at all work with zero additional permissions or configuration.
- To create a restricted key with scoped permissions instead of a full
  secret key: https://docs.stripe.com/keys/restricted-api-keys
- To manage team members and (on Enterprise plans with SSO) provision
  access via SCIM: https://docs.stripe.com/get-started/account/orgs/team
  and https://docs.stripe.com/get-started/account/sso/scim
- To enable deadkey's optional SCIM-based team-account check, set
  DEADKEY_STRIPE_SCIM_BEARER_TOKEN to a SCIM bearer token generated in
  Stripe's Team and security settings.

### Known limitations

- No last-used/activity data exists for any Stripe credential type.
  Confirmed: Stripe's Activity Logs API
  (https://docs.stripe.com/activity-logs) tracks key management events
  (api_key_created, api_key_deleted, api_key_updated, api_key_viewed), not
  key usage events. There is no API-based signal, direct or inferred, for
  when a credential was last used to make a request. This is a structural
  limitation of Stripe's API, not a gap in deadkey.
- Webhook secrets and Connect client IDs cannot be validated as alive/dead
  via any confirmed API call. A webhook secret is never sent to Stripe at
  all (it's a local HMAC signing key); a Connect client ID is a public
  identifier with no per-ID check. deadkey still discovers and tracks
  both (by design, per project scope), but Validate() reports this
  limitation explicitly rather than guessing a verdict. Publishable keys,
  by contrast, DO have a real validation path (POST /v1/tokens) - this was
  initially assumed impossible based on publishable keys' general
  client-side framing, then corrected after finding this endpoint's
  documented auth requirements directly.
- No confirmed API exposes what specific permissions a restricted key
  (rk_) was granted at creation - this is visible only in the Stripe
  Dashboard UI. deadkey can identify that a key IS restricted, but not
  grade how narrowly.
- Team member listing and active/inactive status are accessible via SCIM
  (a real, implemented optional check - see scim.go), but only for
  accounts on an Enterprise plan with SSO and SCIM provisioning enabled.
  Set DEADKEY_STRIPE_SCIM_BEARER_TOKEN to enable; gracefully returns no
  signal if unset or if the call fails. Note: this checks account
  active/inactive status only - standard SCIM's core schema does not
  define a 2FA/MFA field, and no confirmed Stripe API exposes 2FA status
  at all. This is a narrower, different check than AWS's "no MFA enrolled"
  modifier, not a direct equivalent.

---

## SendGrid

Status: not yet researched in depth.

Known so far: the "list API keys" endpoint returns only name and ID, no
last-used field. An Email Activity Feed API exists but tracks email
delivery events, not API key usage, and retains only 7 days. Likely a
genuine ActivityUnavailable case. Needs a full research pass before design.

---

## Twilio

Status: not yet researched in depth.

Known so far: Account/API Key/Credential resources expose date_created and
date_updated only. No last-used field found. "Updated" refers to the
resource being modified (e.g. rotated), not a usage timestamp. Likely a
genuine ActivityUnavailable case. Needs a full research pass before design.
