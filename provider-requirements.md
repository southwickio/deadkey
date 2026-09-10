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

All five original providers (AWS, GitHub, Stripe, SendGrid, Twilio) are now
fully researched, designed, and implemented as of this revision.

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
| Account-inactive detection | not implemented | researched, no signal found - see Known Limitations |

### Provider-side setup

- To grant these permissions to the credential deadkey will scan with, see
  AWS's IAM policy documentation: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html
- No AWS-side toggle or app registration is required. All of the above works
  with a standard IAM user access key, provided it has the listed
  permissions.

### Known limitations

- Cross-scan identity for this credential uses the AWS access key ID as a
  safe, non-secret Identifier (see models.Credential.Identifier), not just
  Location - meaning the same key found via a different profile/file/env
  var across scans is still recognized as the same credential. Access key
  IDs are designed to be non-secret (AWS displays them unmasked in the
  console/CLI), so this is safe to store
- No distinguishable "account suspended" signal exists at the
  sts:GetCallerIdentity layer. Confirmed by checking STS's own complete,
  documented exception list (every subclass of Aws::STS::ServiceError):
  ExpiredTokenException, IDPCommunicationErrorException,
  IDPRejectedClaimException, InvalidAuthorizationMessageException,
  InvalidIdentityTokenException, MalformedPolicyDocumentException,
  PackedPolicyTooLargeException, RegionDisabledException. None of these is
  suspension-related. A real, documented AccountProblem error exists, but
  is S3-specific, not STS-specific, and does not appear on any universal
  "Common Errors" reference page checked. AWS's suspension model appears to
  be enforced per-service rather than through one shared, STS-visible
  signal. This is a structural difference from Twilio/GitHub/SendGrid/
  Stripe, confirmed via documentation, not a research gap.
- Flagged, unresolved, and separate from the above: this provider's
  existing isAuthFailure function already treats the generic AccessDenied
  error code as proof of a dead credential (ValidationInvalid). It is
  plausible, but not confirmed, that a suspended account's
  GetCallerIdentity call could also surface as AccessDenied rather than one
  of the more specific codes already handled (InvalidClientTokenId,
  ExpiredToken, SignatureDoesNotMatch) - which would mean a suspended-but-
  otherwise-fine credential is already being misreported as flatly invalid
  today. This can only be settled by testing against a real (or
  deliberately suspended) AWS account, not by further documentation review.
  Tracked as a follow-up, not silently assumed either way.

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
| Account-inactive detection | none beyond holding the token | GET /user's 403/429 responses are classified into four distinct conditions rather than one bucket - see Known Limitations |

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
- GET /user's 403/429 status is documented and confirmed (via real, current
  reports) to mean four different things, not one: account suspension
  (-> ValidationAccountInactive), organization SSO/SAML enforcement
  (-> ValidationValid; the token is fine, the org just requires
  re-authorization), a primary rate limit (-> a transient Go error,
  detected via the X-RateLimit-Remaining header), or a secondary rate
  limit (-> a transient Go error, detected via a message substring match).
  The account-suspension message text ("Sorry. Your account was suspended")
  has been confirmed stable and unchanged across a decade of real reports,
  including a live incident dated one month before this research. The
  secondary-rate-limit detection is deliberately the least confident check
  in this provider: GitHub's own documentation states outright that this
  message's exact wording is "subject to change without notice," and real
  reports from 2023-2025 show at least three different wordings for the
  same underlying condition. If GitHub ever changes this wording again in
  a way this substring match misses, the practical fallback is a Go error
  either way (from the unexpected-status default case), not a false dead
  verdict.

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
| Account-inactive detection (secret/restricted/organization keys) | connected_account_read, for Restricted keys only (unrestricted secret and organization keys always have access) | best-effort bonus check against GET /v1/account after a successful balance check. See Known Limitations |
| Live-mode risk flag | none | derived from the credential's own value (_live_ substring), no API call |
| Unrestricted-key risk flag | none | derived from the credential's own prefix, no API call |
| Organization-key risk flag | none | derived from the credential's own prefix, no API call |
| Team-account status risk flag (optional) | Enterprise plan with SSO + SCIM provisioning enabled | see Known Limitations for exact scope |

### Provider-side setup

- No setup is required beyond having a credential. All checks that are
  possible at all work with zero additional permissions or configuration.
- To create a restricted key with scoped permissions instead of a full
  secret key: https://docs.stripe.com/keys/restricted-api-keys
- To grant an existing restricted key read access to account status for
  deadkey's account-inactive check, add the connected_account_read
  permission: https://docs.stripe.com/keys/permissions-reference
- To manage team members and (on Enterprise plans with SSO) provision
  access via SCIM: https://docs.stripe.com/get-started/account/orgs/team
  and https://docs.stripe.com/get-started/account/sso/scim
- To enable deadkey's optional SCIM-based team-account check, set
  DEADKEY_STRIPE_SCIM_BEARER_TOKEN to a SCIM bearer token generated in
  Stripe's Team and security settings.

### Known limitations

- Stripe has a newer, preview-only API surface (v2/iam/api_keys) exposing a
  distinct "Managed API Key" credential type (mk_ prefix) with its own
  unique ID, last_used, status, and expires_at fields - none of which apply
  to the ordinary secret/restricted/publishable keys this provider
  discovers today. Confirmed: managed keys are a structurally different
  credential, issued directly by a hosting platform to an application
  rather than something a developer manually places in an env var or
  config file, and the feature itself is still request-access-only
  ("Request to join the preview for managed API keys" - docs.stripe.com/
  keys/managed-api-keys). Explicitly parked as a future, separate provider
  addition (a sixth Stripe credential subtype, with its own full Steps 1-5
  research pass) if/when this reaches general availability and becomes
  common enough to matter - not a gap in what this provider currently
  covers
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
- Account-inactive detection relies on the Account object's
  requirements.disabled_reason field, read via a best-effort bonus call to
  GET /v1/account made after a successful balance check. This is a field
  on a SUCCESSFUL response, not an error code - a restricted or paused
  Stripe account's key still authenticates normally against GET
  /v1/balance, which is exactly why this needed its own explicit check
  rather than being inferable from any failure elsewhere in this provider.
  Confirmed real disabled_reason values include "platform_paused" and
  "requirements.past_due"; fraud/ToS-rejected accounts surface the same way
  with charges_enabled set to false. If this bonus call fails for any
  reason (network issue, or - for Restricted keys specifically - missing
  the connected_account_read permission), the result degrades gracefully
  to the original balance-based ValidationValid, never an error or a
  false negative.

---

## SendGrid

### deadkey usage

- `deadkey scan --provider sendgrid` - scan for SendGrid credentials only
- `deadkey add` -> select "SendGrid" -> manually register a credential
- `deadkey ignore <location>` -> stop flagging a specific credential slot

Discovery checks four environment variables: SENDGRID_API_KEY and
SENDGRID_TOKEN for modern API keys (classified by the "SG." prefix, not by
character length, since real-world reports disagree on whether keys are
69 or 70 characters), and SENDGRID_USERNAME / SENDGRID_PASSWORD for the
legacy username/password credential SendGrid still accepts for a narrow
set of operations. No official SendGrid CLI config file exists (confirmed
against the real sendgrid/sendgrid-cli source), so unlike AWS or Stripe,
discovery is env-var-only.

### What deadkey checks, and what each needs

| Check | Required permission | Notes |
|---|---|---|
| Discovery | none | reads env vars only, no API call |
| Basic validation (API keys) | none beyond holding the key | GET /v3/scopes, confirmed self-referential - a key can always check its own scopes |
| Basic validation (legacy username/password) | none beyond holding the credential | HTTP Basic Auth against the same endpoint. Less confirmed than the API key path - SendGrid documents Basic Auth for updating a key's scopes specifically, not explicitly for this read-only use |
| Account-inactive detection | none beyond holding the credential | classifies 401 responses on either validation path into two documented account-level conditions versus a genuinely bad credential - see Known Limitations |
| Last-used data | none beyond holding the credential | GET /v3/access_settings/activity's last_at field. Account-level, not per-key - reported as ActivityInferred, not Confirmed |
| Broad-scope risk flags | none | derived from scopes already captured during validation, no extra API call |
| Legacy-credential and inferred-no-MFA flags | none, legacy credentials only | inferred from SendGrid's documented behavior that MFA-enabled accounts reject Basic Auth entirely |

### Provider-side setup

- No setup is required beyond having a credential. All checks work with
  zero additional permissions or configuration.
- To create a Restricted Access key with only the scopes you need instead
  of Full Access: https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys
- To move teammates off legacy passwords entirely, SendGrid supports SAML
  SSO on Pro, Premier, and Marketing Campaigns Advanced plans:
  https://www.twilio.com/docs/sendgrid/ui/account-and-settings/sso

### Known limitations

- No per-key last-used data exists. GET /v3/access_settings/activity is
  account-level (most recent access by any method, any credential), not
  tied to a specific key - a real, usable signal, but an inferred one, not
  a confirmed per-credential fact the way AWS's is.
- No confirmed API exposes whether MFA/2FA is enabled on an account
  directly. deadkey infers MFA is off for legacy username/password
  credentials specifically, based on SendGrid's documented behavior that
  MFA-enabled accounts reject Basic Authentication entirely. This
  inference has no equivalent for API key credentials, which never
  interact with MFA/Basic Auth at all.
- The legacy username/password discovery env var names (SENDGRID_USERNAME,
  SENDGRID_PASSWORD) are a reasonable convention, not an independently
  confirmed universal standard the way SENDGRID_API_KEY is.
- SendGrid's webhook signature verification key (ECDSA) and SSO SAML
  certificate are deliberately NOT treated as credentials to protect -
  both are public keys by design (SendGrid keeps the corresponding private
  material), and flagging them as at-risk secrets would be incorrect. The
  webhook OAuth client_id/client_secret some integrations configure is
  also out of scope - it is the developer's own arbitrary OAuth app
  registration, not a SendGrid-issued credential, and has no confirmed
  universal naming convention to discover.
- Team member listing, roles, and SCIM-style provisioning exist on
  Enterprise-tier plans via a private beta, not generally available at
  time of writing - not implemented in V0.
- Account-inactive detection covers two documented conditions, with two
  different confidence levels. "Maximum credits exceeded" (billing-frozen
  or plan-capped) has confirmed literal message text from multiple
  independent, current sources. "Account Disabled" (suspended, banned, or
  deactivated by SendGrid's Consumer Trust team) is confirmed only at the
  level of SendGrid's own support-article label - the literal JSON message
  field of a real suspended account's response is not independently
  confirmed anywhere publicly findable, so this is matched via best-effort
  phrase matching rather than an exact string. Needs verification against
  a real suspended account's response before this can be treated as fully
  confirmed, the same way Twilio's CLI config file schema is flagged below.

---

## Twilio

Discovery checks three independent methods: environment variables
(TWILIO_ACCOUNT_SID/TWILIO_AUTH_TOKEN, and both documented API Key naming
conventions - TWILIO_API_KEY/TWILIO_API_SECRET and
TWILIO_API_KEY_SID/TWILIO_API_KEY_SECRET), .env-style files when pattern
matching is enabled, and twilio-cli's own config.json (default
~/.twilio-cli/config.json). TWILIO_REGION/TWILIO_EDGE are captured
alongside any found credential and used to target the correct regional API
hostname during validation.

Twilio has two fundamentally different credential shapes: an Account SID
(AC...) + Auth Token pair (equivalent to full account access, including a
documented secondary Auth Token for zero-downtime rotation), and an API Key
(SK...) + Secret pair, of type Main, Standard, or Restricted. The API Key's
specific type cannot be read directly from Twilio's API (confirmed: the Key
resource's fetch response has no type field, checked against two
independently generated SDKs) - it is inferred during the risk-modifier
check instead.

### deadkey usage

- `deadkey scan --provider twilio` - scan for Twilio credentials only
- `deadkey scan --path ~/custom/config.json` - override the default
  twilio-cli config file location
- `deadkey add` -> select "Twilio" -> manually register a credential
- `deadkey ignore <location>` -> stop flagging a specific credential slot

### What deadkey checks, and what each needs

| Check | Required permission | Notes |
|---|---|---|
| Discovery | none | reads local files/env vars, no API call |
| Basic validation | none beyond holding the credential (Restricted keys will correctly get a permission-denied response here - see Known Limitations) | GET .../Balance.json, chosen specifically over GET /Accounts/{Sid}.json, which Standard and Restricted keys are documented as denied - with the SAME error code as a genuinely wrong credential |
| Account-inactive detection | none beyond holding the credential | Twilio error 10001 ("Account is not active") is a distinct, documented code separate from its generic authentication-failure code, reachable on the same Balance call used for basic validation |
| Test-credential detection | none beyond holding the credential | an Account SID+Auth Token pair that authenticates but is denied access to Balance can only mean a Test credential - confirmed via Twilio's own documented list of the few resources Test credentials CAN reach (Balance is not one of them) |
| Key-type risk flag (Main vs. Standard vs. Restricted) | none for Restricted (visible via the key's own policy field); one extra probe call to disambiguate Main from Standard | see Known Limitations for the exact inference method |
| Restricted-key permission-breadth risk flag | none beyond holding the credential | read directly from the same policy field used for key-type inference |
| Trial-account and subaccount context | Account SID+Auth Token pair, or a Main API Key only | GET /Accounts/{Sid}.json is denied to Standard and Restricted keys, same restriction as basic validation's endpoint choice avoided |
| Last-used data | Unavailable | no API field exists at any tier, for either credential shape - see Known Limitations |

### Provider-side setup

- No setup is required beyond having a credential. All checks that are
  possible at all work with zero additional permissions or configuration.
- To create a Restricted API Key with only the permissions you need instead
  of a Main or Standard key: https://www.twilio.com/docs/iam/api-keys
- Region/Edge configuration (only relevant for accounts using Twilio's
  Global Infrastructure regions/edges) is documented at:
  https://www.twilio.com/docs/global-infrastructure/understanding-twilio-regions

### Known limitations

- Cross-scan identity for both Twilio credential shapes uses a safe,
  non-secret Identifier (the Account SID for an Auth-Token credential, the
  API Key SID for an API-Key credential - see models.Credential.Identifier),
  not just Location. Both are designed to be non-secret: they're the
  username half of this credential's Basic Auth pair, shown unmasked
  throughout the Console and API responses
- No per-credential last-used data exists anywhere in Twilio's API, at any
  permission tier, for either Auth Tokens or API Keys. Confirmed: the Key
  resource exposes only date_created/date_updated (checked against two
  independently generated SDKs from the same spec), and date_updated
  itself is a weaker signal than it first appears - it also changes on a
  Restricted key's permission edit or a rename, not only on rotation or
  use. Twilio's Monitor Events API (a paid-tier audit log) was checked as
  a possible enhanced-mode signal and found insufficient: its actor
  attribution collapses to the ACCOUNT level for any API-authenticated
  request, never the specific API Key that made the call - so even paying
  for the higher tier cannot answer "which of my several forgotten keys is
  the dead one," which is specifically the question this product exists to
  answer. This is a structural Twilio limitation, not a gap in deadkey.
- An API Key discovered with no accompanying Account SID nearby (e.g. a
  partial .env file with only TWILIO_API_KEY/TWILIO_API_SECRET) cannot be
  validated at all. Every Twilio API request path requires
  .../Accounts/{AccountSid}/..., regardless of which credential
  authenticates it, and there is no documented way to resolve an account
  from an API Key alone. deadkey still discovers and reports this
  credential rather than dropping it silently; Validate() reports the
  specific reason it cannot be checked.
- Key-type inference (Main vs. Standard vs. Restricted) is not a direct
  field read. A non-null policy field means Restricted, with its
  permission breadth already available at no extra cost. A null policy
  means Main or Standard, disambiguated only by one additional probe call
  against a Main-only endpoint (GET /Accounts/{Sid}.json) - success means
  Main, the documented Standard-key-denial pattern means Standard.
- Twilio's own CLI (twilio-cli) does not have a documented command that
  prints a profile's raw secret the way `gh auth token` does for GitHub.
  This was resolved, not worked around: current twilio-cli versions
  (v6.0.0+, released 2022-01-18, per twilio-cli-core's own changelog)
  store a profile's generated API Key SID and secret directly in
  ~/.twilio-cli/config.json as a structured, readable file - the same tier
  of discovery as AWS's ~/.aws/credentials. Versions older than v6.0.0
  instead used the OS keychain (the "keytar" npm package) and are an
  explicit, stated non-goal for this discovery path, not silently skipped.
  The exact field names inside config.json are the best-supported
  reconstruction from indirect evidence (Twilio does not publish this
  file's schema, since it's an internal CLI implementation detail, not a
  public API contract) - flagged as needing confirmation against a real
  generated file before being treated as fully confirmed.
- Reliable detection of Twilio's Test Credentials feature is scoped to the
  Account SID+Auth Token pair only (API Keys are never issued as Test
  credentials, confirmed). There is no single global "known test SID" to
  pattern-match against - each account's Test Account SID/Auth Token pair
  is unique to that account, confirmed via Twilio's own documentation.
- Suspended/inactive subaccounts may be inactive because their PARENT
  account was suspended (a documented cascade), which deadkey cannot
  independently confirm without also holding the parent account's own
  credentials. When this is detected, the reported reason notes the
  possibility rather than asserting a specific cause it cannot verify.