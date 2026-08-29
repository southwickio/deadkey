package models

//FeedbackPayload is what gets sent to the anonymous, opt-in telemetry endpoint
//when a user gives up/down feedback on a risk assessment. This is deliberately
//its OWN struct rather than a reuse of CredentialAssessment or any of its
//fields, even though the two overlap conceptually. That separation is
//intentional and load-bearing: it makes it structurally impossible for a field
//added to Credential, DiscoveryEvidence, etc. in the future (for example: a new
//Metadata key, or Location) to accidentally leak into telemetry just because it
//exists somewhere else on the model. Anyone extending telemetry has to
//deliberately add a field here and populate it. There is no shortcut that
//forwards "everything we know."
//
//Fields on this struct must stay free of:
//  - the credential value itself
//  - Location strings (they can reveal machine/user/environment structure)
//  - account identifiers, ARNs, org/hostnames
//  - anything from a Credential's Metadata map
//  - any free-text field the user typed (for example: a custom "Other" provider
//    name must be normalized/bucketed before it reaches this struct, never
//    passed through as raw text. That normalization happens upstream of this
//    type, not here)
type FeedbackPayload struct {

	//InstallID is a random identifier generated once locally on first run and
	//stored locally. Not tied to any account, email, or other identifying
	//information. It exists purely so aggregate telemetry can distinguish
	//"10 different installs agreed" from "1 install voted 10 times"
	InstallID string

	Provider       string
	CredentialType CredentialSubtype

	//ModifierCodes lists the stable RiskModifier.Code values that fired for
	//this credential (see risk.go for why Code must stay stable)
	ModifierCodes []string

	DiscoveryMethod     string
	DiscoveryConfidence float64

	ValidationStatus ValidationStatus
	ActivityQuality  ActivityQuality

	RiskTier  RiskTier
	RiskScore int

	//AgeBucket is a coarse, human-readable range like "90-180 days".
	//Deliberately not an exact date, to avoid indirectly fingerprinting a
	//specific credential's creation time
	AgeBucket string

	//Vote is the user's feedback: "up" (the assessment was right) or "down"
	//(it was wrong)
	Vote string
}