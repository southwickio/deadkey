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