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