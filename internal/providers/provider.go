package providers

import (
	"context"

	"github.com/southwickio/deadkey/internal/models"
)

//Provider is the contract every credential provider must implement. The shared
//scan orchestrator, risk-scoring engine, and dashboard all interact with
//providers exclusively through this interface. None of them contain
//provider-specific logic (no "if provider == aws" anywhere in shared code).
//Providers produce evidence; the shared engine interprets evidence
//
//Kept deliberately small (4 required methods) rather than expanded to cover
//every possible variation across providers. The intuition that a growing
//provider count needs a more flexible interface is backwards for a behavior
//contract: a small, strictly-typed interface scales better across many
//implementations than a loose one, because it gives the compiler something to
//enforce. Where genuine per-provider variation exists, it belongs in the return
//types (see ActivityResult's Quality field in models/evidence.go) rather than
//in the interface's method list
type Provider interface {

	//Name returns the provider's identifier, e.g. "aws", "github", "stripe"
	Name() string

	//Discover scans according to cfg and returns every credential found.
	//Implementations should respect cfg.Paths when non-empty, fall back to
	//their own sane defaults otherwise, and honor cfg.PatternMatching where
	//applicable (silently ignoring it if the provider has no pattern-based
	//discovery mode)
	Discover(

		ctx context.Context,
		cfg DiscoveryConfig,
	
	) ([]models.Credential, error)

	//Validate checks whether cred is actually live. For example: by calling the
	//provider's API. An error here should be reserved for the check itself
	//failing (network, auth, rate limit). A credential that is confirmed dead
	//is a successful validation call that returns models.ValidationInvalid, not
	//a Go error
	Validate(
		
		ctx context.Context,
		cred models.Credential,
		
	) (models.ValidationResult, error)

	//GetActivity reports how "alive" cred looks. Implementations must set
	//ActivityResult.Quality honestly (see models.ActivityQuality) rather than
	//reporting inferred or absent data as if it were confirmed. A provider with
	//no activity signal at all should return models.ActivityUnavailable, not
	//treat that as an error condition
	GetActivity(
		
		ctx context.Context,
		cred models.Credential,
	
	) (models.ActivityResult, error)

	//Capabilities describes this provider's activity/validation data quality
	//ceiling. Static per provider (not per-credential) for V0 — see
	//capabilities.go
	Capabilities() ProviderCapabilities
}

//RiskModifierProvider is an optional extension interface. A provider that has
//domain-specific knowledge relevant to risk scoring (for example "this AWS
//credential's IAM policy grants AdministratorAccess") implements this in
//addition to Provider. The shared risk-scoring engine checks for this via a
//type assertion and, if present, folds the returned modifiers into the base
//score. This is the ONLY sanctioned path for provider-specific knowledge to
//influence risk scoring. The shared engine never reads a credential's
//Metadata map directly for scoring purposes
//
//Deliberately kept as a single optional interface rather than several narrower
//ones, to avoid the interface surface growing unmanageably as more providers
//are added
type RiskModifierProvider interface {

	RiskModifiers(
		ctx context.Context,
		cred models.Credential,
	
	) ([]models.RiskModifier, error)

}

//ManualField describes one piece of input `deadkey add` needs to collect
//interactively for a given credential shape. Key is used as the map key when
//the collected values are handed to BuildCredential; Label is shown to the
//person; Secret controls whether the input is masked (see cmd/deadkey/add.go's
//readSecret, built to avoid echoing credential values to the terminal or
//leaving it in a broken state if the person hits Ctrl+C mid-entry)
type ManualField struct {

	Key    string
	Label  string
	Secret bool

}

//ManualFieldSet is one selectable "shape" of manual entry for a provider. Most
//providers have exactly one (for example: GitHub has a single token). Providers
//whose credential comes in more than one real shape (such as: Twilio's Account
//SID+Auth Token vs. an API Key, SendGrid's API key vs. legacy
//username/password, or Stripe's five distinct subtypes), declare one
//ManualFieldSet per shape, and `deadkey add` presents them as a sub-choice
//after the provider itself is picked
type ManualFieldSet struct {

	Subtype models.CredentialSubtype
	Label   string
	Fields  []ManualField

}

//ManualEntryProvider is an optional extension interface, implemented by any
//provider that supports `deadkey add` registering one of its credentials by
//hand rather than through Discover(). Kept optional, not folded into Provider
//itself, so a future provider can exist (discoverable and scannable) without
//also being required to support manual entry on day one
//
//Deliberately scoped the same way RiskModifierProvider is: a provider
//implements this once, independently of how many other providers exist
type ManualEntryProvider interface {

	//ManualFieldSets returns every credential shape this provider supports
	//registering manually, in the order they should be presented
	ManualFieldSets() []ManualFieldSet

	//BuildCredential turns the values collected for one ManualFieldSet (keyed
	//by each ManualField's Key) into a real models.Credential. Implementations
	//should validate field shape here (for example: an AWS access key ID's
	//expected prefix/length) and return an error for anything obviously
	//malformed, rather than waiting to discover it on a live API call. subtype
	//identifies which ManualFieldSet the values came from, for providers with
	//more than one
	//
	//BuildCredential's returned Credential never carries the secret, in
	//Metadata or anywhere else; same cornerstone rule as every discovered
	//credential. See ValidateManual for how the freshly-entered secret gets
	//checked at all, given that constraint
	BuildCredential(subtype models.CredentialSubtype, values map[string]string) (models.Credential, error)

	//ValidateManual performs one immediate, live check using values directly.
	//The same raw map `deadkey add` just collected, still sitting in its
	//caller's local memory, never touching a Credential or its Metadata. This
	//is what lets `deadkey add` validate a manually-entered credential once, at
	//entry time, without ever placing the secret anywhere Discover-based
	//Validate's Metadata-driven resolution would normally look for it
	//
	//A manually-added credential has no file or env var for a future `deadkey
	//scan` to re-read the secret from later. So, unlike a discovered
	//credential, it can only ever be validated at add-time, once, and again
	//only by re-running `deadkey add` by hand. This is not an oversight. It is
	//the direct, unavoidable consequence of this project's cornerstone rule
	//that a secret is never persisted anywhere, including Metadata
	ValidateManual(ctx context.Context, subtype models.CredentialSubtype, values map[string]string) (models.ValidationResult, error)

}