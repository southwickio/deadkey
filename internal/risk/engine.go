//Package risk is the shared scoring engine referred to throughout this
//project's architecture docs: "providers produce evidence, the engine
//interprets evidence." This package must never contain provider-specific
//conditionals (no "if provider == aws" anywhere below). All provider-specific
//knowledge enters exclusively via the RiskModifier list a provider optionally
//supplies (see internal/providers/provider.go's RiskModifierProvider interface)
package risk

import (

	"fmt"  //building the human-readable Reasoning string
	"time"  //computing elapsed time since last activity/first seen

	"github.com/southwickio/deadkey/internal/models"

)

//staleThreshold mirrors the 90-day figure decided on
//("age > 90 days + never used = likely dead"). Kept as one named constant
//rather than a magic number scattered across this file
const staleThreshold = 90 * 24 * time.Hour

//baseline scores per tier, before RiskModifiers are folded in. Illustrative
//starting points. Not a claim of precision. RiskAssessment.Reasoning always
//explains why a tier was chosen in plain language; Score exists for
//sorting/filtering. It is not intended to be used as the primary thing a person
//reads (see risk.go's own doc comment)
const (

	baseDead   = 80
	baseRotate = 50
	baseKeep   = 20

)

//Stated plainly rather than silently assumed: this engine has no access to a
//credential's actual creation/rotation date (for example: AWS IAM CreateDate).
//That fact doesn't exist anywhere in the current model. ActivityResult only
//carries LastUsedAt, not CreatedAt. Until a future model addition closes this
//gap, "how long has this been sitting around" is approximated using firstSeenAt
//(when THIS credential first appeared in deadkey's own local history), which is
//a proxy for "how long we've known about it," not the credential's true age.
//This is weaker than the original roadmap's "age > 90 days" language implied,
//and is flagged here so nobody mistakes this for a stronger guarantee than it
//is
//
//Score computes a RiskAssessment for a credential that validated successfully
//(models.ValidationValid). Callers should not call Score for any other
//ValidationStatus. They're handled by the caller (see cmd/deadkey/scan.go)
//before this function is ever reached. Why the other validation types don't
//work:
//  - ValidationInvalid: the credential is already confirmed dead/revoked. No
//    scoring math needed. Report RiskDead directly
//  - ValidationAccountInactive: deliberately never scored via age/activity
//    math. See models.RiskAccountInactive's doc comment. Report that tier
//    directly
//  - ValidationError: A Go error; not a ValidationStatus. The check itself
//    failed. There is nothing to score. This credential's assessment should
//    record "couldn't check". Not a tier
func Score(

	validation models.ValidationResult,
	activity models.ActivityResult,
	modifiers []models.RiskModifier,
	firstSeenAt time.Time,

) models.RiskAssessment {

	tier, reasoning := scoreTier(activity, firstSeenAt)

	base := baseKeep
	switch tier {

	case models.RiskDead:
		base = baseDead
	case models.RiskRotate:
		base = baseRotate

	}

	score := base
	for _, m := range modifiers {

		score += m.Adjustment

	}
	score = clamp(score, 0, 100)

	return models.RiskAssessment{

		Tier:                    tier,
		Score:                   score,
		Reasoning:               reasoning,
		BasedOnActivityQuality:  activity.Quality,
		ModifiersApplied:        modifiers,

	}

}

//scoreTier is the actual age/activity decision logic, kept separate from Score
//so the tier decision and the score-number bookkeeping don't get mixed together
func scoreTier(activity models.ActivityResult, firstSeenAt time.Time) (models.RiskTier, string) {

	now := time.Now()

	switch activity.Quality {

	case models.ActivityConfirmed, models.ActivityInferred:

		qualityWord := "Confirmed"
		if activity.Quality == models.ActivityInferred {

			qualityWord = "Inferred (not confirmed)"

		}

		if activity.LastUsedAt == nil {

			//Never used, per this provider's own confirmed/inferred data. Not
			//"we have no data," which is the Unavailable case below
			age := now.Sub(firstSeenAt)
			if age >= staleThreshold {

				return models.RiskDead, fmt.Sprintf(
					"%s: never used, first seen %.0f days ago", qualityWord, age.Hours()/24,
				)

			}
			return models.RiskKeep, fmt.Sprintf(
				"%s: never used yet, but first seen recently (%.0f days ago)", qualityWord, age.Hours()/24,
			)

		}

		sinceUse := now.Sub(*activity.LastUsedAt)
		if sinceUse >= staleThreshold {

			return models.RiskRotate, fmt.Sprintf(
				"%s: last used %.0f days ago", qualityWord, sinceUse.Hours()/24,
			)

		}
		return models.RiskKeep, fmt.Sprintf(
			"%s: used recently (%.0f days ago)", qualityWord, sinceUse.Hours()/24,
		)

	case models.ActivityUnavailable:

		//No activity signal exists at all for this provider/credential.
		//Deliberately never reports RiskDead from absence of data alone because
		//a score must visibly communicate lower confidence, not be treated as
		//equivalent to confirmed data. Falls back purely to how long we've
		//known about this credential
		age := now.Sub(firstSeenAt)
		if age >= staleThreshold {

			return models.RiskRotate, fmt.Sprintf(
				"No activity data available for this provider; first seen %.0f days ago", age.Hours()/24,
			)

		}
		return models.RiskKeep, "No activity data available for this provider; first seen recently"

	default:

		//Defensive fallback for an unrecognized ActivityQuality value (for
		//example: a future addition this engine hasn't been updated for yet).
		//Never silently treated as confident. Same conservative floor as
		//Unavailable
		return models.RiskKeep, "Unrecognized activity data quality; unable to assess confidently"

	}

}

//AccountInactive builds the short-circuit RiskAssessment for
//ValidationAccountInactive credentials; never run through scoreTier's
//age/activity math. See models.RiskAccountInactive's doc comment for why this
//is a fully separate path, not just a different tier value plugged into the
//same scoring formula
func AccountInactive(validation models.ValidationResult) models.RiskAssessment {

	reasoning := "Account is inactive (suspended, closed, or restricted) for a reason unrelated to this credential's own age or usage"
	if validation.ErrorDetail != "" {

		reasoning = fmt.Sprintf("%s: %s", reasoning, validation.ErrorDetail)

	}

	return models.RiskAssessment{

		Tier:      models.RiskAccountInactive,
		Score:     0,
		Reasoning: reasoning,

	}

}

//Invalid builds the short-circuit RiskAssessment for a credential that Validate
//has already confirmed is dead/revoked (models.ValidationInvalid). No
//age/activity math applies. The credential doesn't work, full stop
func Invalid(validation models.ValidationResult) models.RiskAssessment {

	reasoning := "Credential does not authenticate (confirmed invalid or revoked)"
	if validation.ErrorDetail != "" {

		reasoning = fmt.Sprintf("%s: %s", reasoning, validation.ErrorDetail)

	}

	return models.RiskAssessment{

		Tier:      models.RiskDead,
		Score:     baseDead,
		Reasoning: reasoning,

	}

}

func clamp(v, min, max int) int {

	if v < min {

		return min

	}
	if v > max {

		return max

	}
	return v

}