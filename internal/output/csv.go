package output

import (

	"encoding/csv"  //writing CSV
	"fmt"  //building modifier summary strings
	"io"  //accepting either stdout or a file as the destination
	"strings"  //joining modifier summaries

)

var csvHeader = []string{

	"provider", "subtype", "location", "ignored",
	"discovery_confidence",
	"validation_status", "validation_checked_at", "validation_error_detail",
	"activity_quality", "activity_last_used_at",
	"risk_tier", "risk_score", "risk_reasoning", "risk_modifiers",

}

//RenderCSV writes r.Results as CSV to w. Flattens risk_modifiers into a single
//"code:reason;code:reason" field, since CSV has no native way to represent a
//nested list
func RenderCSV(w io.Writer, r Report) error {

	cw := csv.NewWriter(w)

	if err := cw.Write(csvHeader); err != nil {

		return err

	}

	for _, a := range r.Results {

		lastUsed := ""
		if a.ActivityLastUsedAt != nil {

			lastUsed = a.ActivityLastUsedAt.Format("2006-01-02T15:04:05Z07:00")

		}

		riskScore := ""
		if a.RiskScore != nil {

			riskScore = fmt.Sprintf("%d", *a.RiskScore)

		}

		var modParts []string
		for _, m := range a.RiskModifiers {

			modParts = append(modParts, fmt.Sprintf("%s:%s", m.Code, m.Reason))

		}

		checkedAt := ""
		if !a.ValidationCheckedAt.IsZero() {

			checkedAt = a.ValidationCheckedAt.Format("2006-01-02T15:04:05Z07:00")

		}

		record := []string{

			a.Provider, a.Subtype, a.Location, fmt.Sprintf("%v", a.Ignored),
			a.DiscoveryConfidence,
			a.ValidationStatus, checkedAt, a.ValidationErrorDetail,
			a.ActivityQuality, lastUsed,
			a.RiskTier, riskScore, a.RiskReasoning, strings.Join(modParts, ";"),

		}

		if err := cw.Write(record); err != nil {

			return err

		}

	}

	cw.Flush()
	return cw.Error()

}

var otherCSVHeader = []string{"name", "location", "first_seen_at"}

//RenderOtherCSV writes r.OtherCredentials as CSV to w. Deliberately a separate
//file from RenderCSV's output, not a second section appended to the same one.
//OtherCredential's three columns (name, location, first-seen date) share
//nothing with AssessmentRow's dozen-plus scored columns (provider, risk tier,
//validation status, activity data...); forcing both shapes into one flat table
//would mean either a wall of blank cells for every "Other" row or the same for
//every scored row, depending on which column set won. Two small, purpose-built
//files each stay genuinely readable on their own
func RenderOtherCSV(w io.Writer, r Report) error {

	cw := csv.NewWriter(w)

	if err := cw.Write(otherCSVHeader); err != nil {

		return err

	}

	for _, o := range r.OtherCredentials {

		firstSeen := ""
		if !o.FirstSeenAt.IsZero() {

			firstSeen = o.FirstSeenAt.Format("2006-01-02T15:04:05Z07:00")

		}

		if err := cw.Write([]string{o.OtherName, o.Location, firstSeen}); err != nil {

			return err

		}

	}

	cw.Flush()
	return cw.Error()

}