package storage

import (

	"database/sql"  //for sql.NullString/sql.NullInt64 reading nullable columns
	"encoding/json"  //encoding/decoding risk modifiers
	"time"  //parsing/formatting stored timestamps

	"github.com/southwickio/deadkey/internal/models"

)

//AssessmentRow is one persisted assessment, joined with enough of its parent
//credential's identity for output/reporting to use without a separate query
type AssessmentRow struct {

	//AssessmentID and CredentialID identify this specific row and its parent
	//credential in storage. Needed by internal/dashboard so the vote/ignore/
	//unignore actions can target a specific row - AssessmentRow itself is
	//read-only reporting data everywhere else in this project (scan.go's
	//table/JSON/CSV output never needed a stable ID to act on), but a
	//dashboard is exactly the situation where "which one do I click" becomes
	//necessary
	AssessmentID  int64
	CredentialID  int64
	FirstSeenAt   time.Time

	Provider string
	Subtype  string
	Location string
	Ignored  bool

	DiscoveryConfidence string

	ValidationStatus          string
	ValidationCheckedAt       time.Time
	ValidationErrorDetail     string
	ValidationCheckedEndpoint string

	ActivityLastUsedAt *time.Time
	ActivityQuality    string
	ActivitySource     string

	RiskTier      string
	RiskScore     *int
	RiskReasoning string
	RiskModifiers []models.RiskModifier

}

//InsertAssessment persists one CredentialAssessment against
//scanID/credentialID. Never updates a previous row. Every scan's result is a
//new, permanent row, which is what lets history/trends exist later without a
//separate design change. ignored records whether this credential was on the
//ignore list at the time of this scan, per the design decision to still run the
//full pipeline on ignored credentials and only suppress them from default
//output
func InsertAssessment(db *DB, scanID, credentialID int64, a models.CredentialAssessment, ignored bool) error {

	modifiersJSON, err := json.Marshal(a.Risk.ModifiersApplied)
	if err != nil {

		return err

	}

	var lastUsed interface{}
	if a.Activity.LastUsedAt != nil {

		lastUsed = a.Activity.LastUsedAt.UTC().Format(time.RFC3339)

	}

	var checkedAt interface{}
	if !a.Validation.CheckedAt.IsZero() {

		checkedAt = a.Validation.CheckedAt.UTC().Format(time.RFC3339)

	}

	var riskScore interface{}
	if a.Risk.Tier != "" {

		riskScore = a.Risk.Score

	}

	_, err = db.Exec(`
		INSERT INTO assessments (
			scan_id, credential_id, discovery_confidence,
			validation_status, validation_checked_at, validation_error_detail, validation_checked_endpoint,
			activity_last_used_at, activity_quality, activity_source,
			risk_tier, risk_score, risk_reasoning, risk_modifiers,
			ignored
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		scanID, credentialID, string(a.Credential.DiscoveryConfidence),
		string(a.Validation.Status), checkedAt, a.Validation.ErrorDetail, a.Validation.CheckedEndpoint,
		lastUsed, string(a.Activity.Quality), a.Activity.Source,
		string(a.Risk.Tier), riskScore, a.Risk.Reasoning, string(modifiersJSON),
		ignored,
	)

	return err

}

//ListForScan returns every assessment recorded under scanID, joined with its
//credential's identity, in insertion order
func ListForScan(db *DB, scanID int64) ([]AssessmentRow, error) {

	rows, err := db.Query(`
		SELECT a.id, a.credential_id, c.first_seen_at, c.provider, c.subtype, c.location,
			a.ignored, a.discovery_confidence,
			a.validation_status, a.validation_checked_at, a.validation_error_detail, a.validation_checked_endpoint,
			a.activity_last_used_at, a.activity_quality, a.activity_source,
			a.risk_tier, a.risk_score, a.risk_reasoning, a.risk_modifiers
		FROM assessments a
		JOIN credentials c ON c.id = a.credential_id
		WHERE a.scan_id = ?
		ORDER BY a.id`, scanID)
	if err != nil {

		return nil, err

	}
	defer rows.Close()

	var out []AssessmentRow

	for rows.Next() {

		var r AssessmentRow
		var firstSeenAt string
		var ignoredInt int
		var checkedAt, lastUsed sql.NullString
		var riskScore sql.NullInt64
		var modifiersJSON string

		if err := rows.Scan(
			&r.AssessmentID, &r.CredentialID, &firstSeenAt, &r.Provider, &r.Subtype, &r.Location,
			&ignoredInt, &r.DiscoveryConfidence,
			&r.ValidationStatus, &checkedAt, &r.ValidationErrorDetail, &r.ValidationCheckedEndpoint,
			&lastUsed, &r.ActivityQuality, &r.ActivitySource,
			&r.RiskTier, &riskScore, &r.RiskReasoning, &modifiersJSON,
		); err != nil {

			return nil, err

		}

		r.Ignored = ignoredInt != 0
		if t, err := time.Parse(time.RFC3339, firstSeenAt); err == nil {

			r.FirstSeenAt = t

		}

		if checkedAt.Valid {

			if t, err := time.Parse(time.RFC3339, checkedAt.String); err == nil {

				r.ValidationCheckedAt = t

			}

		}
		if lastUsed.Valid {

			if t, err := time.Parse(time.RFC3339, lastUsed.String); err == nil {

				r.ActivityLastUsedAt = &t

			}

		}
		if riskScore.Valid {

			v := int(riskScore.Int64)
			r.RiskScore = &v

		}
		if modifiersJSON != "" {

			//A decode failure here is deliberately non-fatal - modifiers are
			//supplementary detail, not something that should sink an entire
			//scan's output over one malformed row
			_ = json.Unmarshal([]byte(modifiersJSON), &r.RiskModifiers)

		}

		out = append(out, r)

	}

	return out, rows.Err()

}
//GetAssessment returns the single assessment row for credentialID within
//scanID. Used by internal/dashboard's vote/ignore handlers, which need one
//specific row's full detail (to build a models.FeedbackPayload, or to know
//a credential's provider/location to ignore) rather than a whole scan's
//worth of rows. Returns (AssessmentRow{}, false, nil) if no matching row
//exists, mirroring storage.GetScan's not-found convention
func GetAssessment(db *DB, scanID, credentialID int64) (AssessmentRow, bool, error) {

	rows, err := ListForScan(db, scanID)
	if err != nil {

		return AssessmentRow{}, false, err

	}

	for _, r := range rows {

		if r.CredentialID == credentialID {

			return r, true, nil

		}

	}

	return AssessmentRow{}, false, nil

}
