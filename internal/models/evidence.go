package models

import "time"

//DiscoveryEvidence records how and where a credential was found. It is captured
//once, at discovery time, and is never mutated afterward. Even if later
//evidence (validation, activity) tells a different story about how trustworthy
//the credential turned out to be. See credential.go's DiscoveryConfidence for
//the confidence classification itself; this struct is where that classification
//actually gets attached to a discovery event, along with supporting detail
type DiscoveryEvidence struct {

	//Method describes the discovery mechanism. For example: "structured_file",
	//"regex_match", "manual". Free-form string rather than a closed enum,
	//since each provider may have several methods of its own (multiple file
	//formats, multiple regex patterns, etc.)
	Method string

	//Confidence is a 0.0-1.0 score for how likely this discovery is to be a
	//genuine credential of the claimed type, independent of whether it later
	//validates as live. A weak regex match starts low; a structured file read
	//starts high. This number is never adjusted after the fact. See
	//ValidationResult below for what happens when validation succeeds or fails
	//afterward
	Confidence float64

	//DiscoveredAt is when this discovery occurred
	DiscoveredAt time.Time

}

//ValidationStatus is the outcome of actually checking whether a credential
//works. For example: calling AWS's sts:GetCallerIdentity
type ValidationStatus string

const (

	ValidationValid   ValidationStatus = "valid"
	ValidationInvalid ValidationStatus = "invalid"

	//ValidationError means the check itself failed (network issue, rate limit,
	//auth problem unrelated to whether the credential works) rather than the
	//credential being confirmed dead. Callers should treat this differently
	//from ValidationInvalid. It means "we don't know," not "we checked and it's
	//dead"
	ValidationError ValidationStatus = "error"

	//ValidationAccountInactive means the credential itself authenticated (it
	//is not wrong/revoked, and it is not simply lacking a permission), but the
	//account it belongs to is suspended, closed, or otherwise inactive for a
	//reason unrelated to whether anyone still uses this specific credential.
	//
	//This is deliberately its own status rather than folded into
	//ValidationInvalid or ValidationRotate/Dead risk tiers: a suspended account
	//is not "safe to revoke because it's old and forgotten," it's already
	//non-functional for an unrelated (often billing or policy) reason, and the
	////risk engine and dashboard must not present the two cases the same way
	//
	ValidationAccountInactive ValidationStatus = "account_inactive"

)

//ValidationResult is the independent record of whether a credential was
//confirmed to actually work. Crucially, this never overwrites
//DiscoveryEvidence.Confidence. A credential found via a weak pattern match that
//goes on to validate successfully keeps both facts on record: "found via a
//shaky method" AND "confirmed live." Collapsing these into one number would
//destroy exactly the information that makes it possible to later ask questions
//like "how often do our regex-based discoveries turn out to be real?"
type ValidationResult struct {

	Status ValidationStatus

	//CheckedAt is when this validation was performed. Kept separate from
	//DiscoveryEvidence.DiscoveredAt since a credential may be discovered once
	//but validated on every subsequent scan
	CheckedAt time.Time

	//ErrorDetail holds a human-readable explanation when Status is
	//ValidationError. Left empty otherwise
	ErrorDetail string

	//CheckedEndpoint optionally records the concrete host/endpoint this check
	//actually ran against (for example: "api.sydney.jp1.twilio.com" versus
	//the default "api.twilio.com")
	//
	//Left empty for providers with only one possible endpoint. This exists so a
	//result is auditable: if a provider has region- or environment-specific
	//endpoints (for example: Twilio's Regions/Edges), a "valid"/"invalid"
	//result alone doesn't tell you whether it was checked against the right
	//place. Optional and additive; no existing provider needs to set it
	CheckedEndpoint string

}

//ActivityQuality tells the risk-scoring engine (and the dashboard) how much to
//trust the LastUsedAt data below. This exists because most of the 5 initial
//providers cannot give a confirmed last-used timestamp the way AWS can. The
//scoring engine must know this up front rather than treating "no data" the same
//as "confirmed inactive"
type ActivityQuality string

const (

	//ActivityConfirmed means LastUsedAt (or its absence) comes directly from
	//the provider's own activity API. For example: AWS's
	//iam:GetAccessKeyLastUsed
	ActivityConfirmed ActivityQuality = "confirmed"

	//ActivityInferred means the provider has no direct last-used signal, and
	//LastUsedAt (if set at all) was derived indirectly. For example: by
	//comparing successive scan snapshots over time
	ActivityInferred ActivityQuality = "inferred"

	//ActivityUnavailable means this provider has no way to determine activity
	//at all, confirmed or inferred. Risk scoring must degrade gracefully in
	//this case rather than treating absence of data as evidence of inactivity
	ActivityUnavailable ActivityQuality = "unavailable"
	
)

//ActivityResult captures how "alive" a credential looks, along with how much
//that assessment can be trusted
type ActivityResult struct {

	//LastUsedAt is nil when no usage data is available at all (Quality will be
	//ActivityUnavailable in that case)
	LastUsedAt *time.Time

	Quality ActivityQuality

	//Source is a short human-readable note on where this data came from. For
	//example: "iam:GetAccessKeyLastUsed" or "snapshot diff over 3 scans".
	//Primarily useful for the dashboard and for debugging inferred data
	Source string
}