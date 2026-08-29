package models

//DiscoveryConfidence describes HOW a credential was identified. This is
//separate from ValidationResult (see evidence.go) on purpose. How something was
//found and whether it turned out to be real are two independent facts, and
//neither should overwrite the other
type DiscoveryConfidence string

const (

	//DiscoveryExact means the credential was found via structured, reliable
	//parsing. Examples include but aren't limited to: reading AWS's
	//~/.aws/credentials file, or reading the GitHub CLI's config file
	//(~/.config/gh/hosts.yml)
	DiscoveryExact DiscoveryConfidence = "exact"

	//DiscoveryPatternMatched means the credential was found via regex/pattern
	//matching against free-form text. Inherently noisier than DiscoveryExact.
	//Examples include but aren't limited to: scanning an .env file for a string
	//matching Stripe's, SendGrid's, or Twilio's key shape, or finding an AWS
	//access key sitting in a plain environment variable rather than the
	//structured credentials file
	DiscoveryPatternMatched DiscoveryConfidence = "pattern_matched"

	//DiscoveryManual means the user explicitly registered this credential
	//themselves via `deadkey add`, rather than it being auto-discovered
	DiscoveryManual DiscoveryConfidence = "manual"

)

//CredentialSubtype distinguishes different kinds of credential within the same
//provider (for example: AWS access keys vs. session tokens). Kept as a plain
//string rather than a closed enum since each provider will define its own
//subtypes independently. The shared model doesn't need to know the full set
type CredentialSubtype string

//Credential is the bare identity of something found (or manually registered)
//on a machine. It intentionally does NOT carry validation status, activity
//data, or risk. Those live in their own evidence types (see evidence.go and
//risk.go) and get bundled together in a CredentialAssessment (assessment.go)
//
//Credential itself is never the place for provider-specific scoring logic to
//live. Anything provider-specific that doesn't fit the fields below belongs in
//Metadata, and Metadata is never read by the shared risk-scoring engine
//directly (see risk.go's RiskModifier for the sanctioned extension point)
type Credential struct {

	//Provider is the name of the provider this credential belongs to. For
	//example: "aws", "github", "stripe", "sendgrid", "twilio", or a free-text
	//name supplied by the user when manually registering a credential under
	//"Other" via `deadkey add`
	Provider string

	//Subtype further classifies the credential within its provider. For
	//example: "access_key" for AWS, "personal_access_token" for GitHub
	Subtype CredentialSubtype

	//Location is a human-readable description of where this credential was
	//found or is expected to live. For example: "~/.aws/credentials [default
	//profile]" or "env:GITHUB_TOKEN". This is the field the skip-list
	//(`deadkey ignore`) keys off of by default, since it's stable across
	//credential rotation in a way that the credential's actual value is not
	//
	//Location is local-only: it is never included in telemetry payloads
	//(see feedback.go), since it can reveal machine, user, or environment
	//structure
	Location string

	//DiscoveryConfidence records how this credential was identified. This is
	//set once at discovery time and is never overwritten later; even if the
	//credential goes on to validate successfully. See ValidationResult in
	//evidence.go for the independent "is it real" fact
	DiscoveryConfidence DiscoveryConfidence

	//Metadata holds provider-specific extras that don't belong in the shared
	//schema (e.g. an AWS ARN, GitHub token scopes). Each provider should define
	//its own constants for the keys it writes here, to avoid typos and ad-hoc
	//key names accumulating over time
	//
	//The shared risk-scoring engine never reads this map directly. A provider
	//that wants to influence risk scoring based on its own metadata should do
	//so via the optional RiskModifierProvider interface instead (see risk.go)
	Metadata map[string]string
	
}