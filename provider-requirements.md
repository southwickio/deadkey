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

Status: not yet researched in depth.

Known so far: no per-key last-used field exists. A real Activity Logs API
exists (6-month retention, ~10 minute delay after events occur) that
includes API-key-related events (key creation, role changes, access from
unfamiliar actors) - this is a real, inferable activity signal via
log-searching, not a direct field. Needs a full research pass before design.

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