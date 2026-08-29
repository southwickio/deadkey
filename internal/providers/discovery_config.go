package providers

//DiscoveryConfig carries the fields that are genuinely universal across all
//providers' Discover() calls: where to look, whether to run pattern-based
//discovery, and how broad a scan to perform
//
//Deliberately does NOT include a map[string]any escape hatch for
//provider-specific options. If a provider eventually needs configuration
//this struct can't express (for example: AWS profile scoping), the right move
//is to add a provider-specific typed config at the time that provider actually
//needs it; not to add a loosely-typed catch-all now on the assumption it might
//be needed. A shared untyped map degrades into an undocumented, unvalidated
//dynamic schema as more providers are added; a provider-specific typed struct
//does not
type DiscoveryConfig struct {

	//Paths are explicit location overrides supplied by the user (for example:
	//via `--path``). When empty, a provider should fall back to its own
	//defaults (for example: AWS defaulting to ~/.aws/credentials)
	Paths []string

	//PatternMatching toggles whether pattern/regex-based discovery should run
	//at all, independent of structured/exact discovery. This exists because
	//pattern-based discovery (used by providers without a structured
	//credentials file such as Stripe/SendGrid/Twilio scanning .env files) is
	//noisier and more prone to false positives than reading a known file format
	//
	//This flag is passed to every provider's Discover() call uniformly. A
	//provider with no pattern-based discovery mode simply ignores it. This is
	//deliberately NOT exposed as a queryable capability (see Capabilities() in
	//provider.go), since discovery mechanics are an internal detail of each
	//provider's own Discover() implementation, not something the orchestrator
	//needs to know ahead of time
	PatternMatching bool

	//Scope reserves room for future skip-list scoping (for example: an eventual
	//`--scope=fingerprint option`). Not used by any V0 logic yet. See the
	//Provider interface doc for why this is left as a string rather than a
	//fully designed type today
	Scope string

}