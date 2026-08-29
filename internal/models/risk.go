package models

//RiskTier is the human-facing verdict on a credential. Deliberately coarse
//(three buckets) rather than presenting the raw numeric score as the headline.
//The tier is what a user acts on, the score and reasoning below are the
//supporting detail for someone who wants to know why
type RiskTier string

const (

	//RiskDead means the credential looks safe to revoke: old and, as far as the
	//available evidence shows, unused
	RiskDead RiskTier = "dead"

	//RiskRotate means the credential is still in use but old enough or risky
	//enough (per applied modifiers) to warrant rotating rather than leaving
	//as-is
	RiskRotate RiskTier = "rotate"

	//RiskKeep means nothing about this credential currently warrants action
	RiskKeep RiskTier = "keep"

)

//RiskModifier is a single typed adjustment a provider can contribute to a
//credential's risk score. This is the ONLY sanctioned way for provider-specific
//knowledge (For example: "this AWS key's IAM policy grants
//AdministratorAccess") to influence scoring. The shared scoring engine never
//contains provider-specific conditionals (no "if provider == aws" anywhere in
//the engine). Instead it asks any provider that implements the optional
//RiskModifierProvider interface for a list of these, and folds them into the
//base score generically
//
//See risk.go's Code field doc for why that field matters beyond just this
//release
type RiskModifier struct {

	//Code is a stable, unique identifier for this specific kind of modifier.
	//For example: "aws_admin_policy" or "stripe_live_key". This must stay
	//stable over time (not free text, not reworded between versions) because it
	//is the join key that makes future analysis possible. For example:
	//aggregating anonymous telemetry (see feedback.go) to ask "how often does
	//this modifier actually correlate with a credential later being revoked?"
	//Changing a Code silently breaks that history
	Code string

	//Adjustment is added to (or subtracted from) the base risk score. Sign and
	//magnitude are up to the provider; the engine treats this as an opaque
	//additive term
	Adjustment int

	//Reason is a short human-readable explanation shown in the dashboard. For
	//example: "IAM policy grants AdministratorAccess"
	Reason string

	//Confidence is a 0.0-1.0 score for how sure the provider is about this
	//specific modifier applying. Lets a provider express "this is a
	//high-severity signal, but I'm not fully sure it applies here" rather than
	//presenting every modifier as equally certain
	Confidence float64

}

//RiskAssessment is the final verdict on a credential: never a bare number.
//Always a tier, the reasoning behind it, and an honest accounting of the data
//quality it's based on, since a "dead" verdict built on ActivityUnavailable
//data should not read as equally confident as one built on ActivityConfirmed
//data
type RiskAssessment struct {

	Tier RiskTier

	//Score is the underlying numeric value the Tier was derived from. Exposed
	//for sorting/filtering in the dashboard, not meant to be the primary thing
	//a user reads
	Score int

	//Reasoning is a short human-readable summary of why this tier was assigned.
	//For example: "Unused for 142 days; no confirmed activity data available"
	Reasoning string

	//BasedOnActivityQuality mirrors the ActivityQuality (see evidence.go) that
	//fed into this assessment, so the dashboard can visibly flag when a verdict
	//rests on weaker data rather than presenting all verdicts as equally
	//certain
	BasedOnActivityQuality ActivityQuality

	//ModifiersApplied lists every RiskModifier that was folded into Score,
	//preserved here for transparency/audit rather than only being reflected in
	//the final number
	ModifiersApplied []RiskModifier

}
