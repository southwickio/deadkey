package models

//CredentialAssessment is the full picture of a single scanned or manually
//registered credential: its identity plus every independent layer of evidence
//gathered about it. This is the shape that makes "providers produce evidence,
//the engine interprets evidence" concrete rather than just a design principle.
//It's what gets stored locally (in SQLite), what the dashboard renders, and
//what cloud sync uploads (as metadata only)
//
//The four evidence fields are deliberately kept as separate structs rather than
//flattened into one growing struct, and deliberately never overwrite each
//other:
//  - Discovery records how the credential was found, and does not change even
//    if Validation later succeeds against a shaky discovery method
//  - Validation records whether it's actually real and live
//  - Activity records how "alive" it looks, with an honest quality tier rather
//    than presenting inferred/absent data as equivalent to confirmed data
//  - Risk is the final verdict, computed from the other three plus any
//    provider-specific RiskModifiers
type CredentialAssessment struct {

	Credential Credential

	Discovery  DiscoveryEvidence
	Validation ValidationResult
	Activity   ActivityResult
	Risk       RiskAssessment

}