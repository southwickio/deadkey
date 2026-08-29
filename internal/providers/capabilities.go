package providers

import "github.com/southwickio/deadkey/internal/models"

//ProviderCapabilities describes what a provider can tell us about a
//credential's activity/validation data quality
//
//This is scoped narrowly and deliberately. An earlier design considered
//bundling discovery-mechanics flags (for example: "does this provider use regex
//or structured parsing?") into this same struct, but that mixes two unrelated
//dimensions: what a provider can tell us (relevant to risk scoring) versus
//how a provider finds things (an internal detail of Discover(), and already
//handled uniformly via DiscoveryConfig.PatternMatching. See
//discovery_config.go). Keeping Capabilities() scoped to data quality alone
//means the risk-scoring engine has exactly what it needs and nothing it doesn't
type ProviderCapabilities struct {

	//MaxActivityQuality is the best ActivityQuality this provider can ever
	//report, such as models.ActivityConfirmed for AWS (which has a real
	//last-used API) versus models.ActivityInferred for providers that can only
	//estimate activity via snapshot diffing. The risk-scoring engine uses this
	//to calibrate confidence before it even calls GetActivity, and the
	//dashboard can use it to show a persistent, provider-level caveat rather
	//than a per-credential surprise
	MaxActivityQuality models.ActivityQuality

}