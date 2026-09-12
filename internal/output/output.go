//Package output renders scan results in each of deadkey's supported formats:
//a human-readable table (default), JSON, and CSV. Shares one Report type so all
//three formats always describe the exact same data
package output

import (

	"time"  //timestamps in the report

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/storage"

)

//Report is everything `deadkey scan` produces for a single run, in the shape
//every output format renders from
type Report struct {

	ScanID            int64             `json:"scan_id"`
	StartedAt         time.Time         `json:"started_at"`
	FinishedAt        time.Time         `json:"finished_at"`
	ProvidersChecked  []string          `json:"providers_checked"`
	ProvidersFailed   []models.ProviderFailure `json:"providers_failed"`
	Results           []storage.AssessmentRow `json:"results"`

	//OtherCredentials lists manually-tracked "Other" entries (see
	//cmd/deadkey/add.go). Deliberately never scored, since there is no real API
	//behind them to check. Shown in their own section in table and JSON output.
	//For --csv, these are written to a SEPARATE companion file (see
	//cmd/deadkey/writeReport and output.RenderOtherCSV) rather than appended to
	//the main CSV, since the two row shapes share no columns
	OtherCredentials []storage.OtherCredential `json:"other_credentials,omitempty"`

}

//riskTierFilter maps a --min-risk flag value to the set of tiers at or above
//it. Order here reflects severity, most to least urgent (RiskAccountInactive is
//deliberately its own case, always shown regardless of --min-risk, since
//suppressing an account-inactive finding behind a risk filter would misread it
//as a normal, lower-priority finding rather than the distinct condition it is)
var riskTierSeverity = map[string]int{

	"dead":   3,
	"rotate": 2,
	"keep":   1,

}

//FilterByMinRisk returns only rows at or above minRisk's severity, plus every
//account-inactive and couldn't-check row regardless of minRisk, plus ignored
//rows only when showIgnored is true
func FilterByMinRisk(rows []storage.AssessmentRow, minRisk string, showIgnored bool) []storage.AssessmentRow {

	var out []storage.AssessmentRow

	minSeverity := 0
	if s, ok := riskTierSeverity[minRisk]; ok {

		minSeverity = s

	}

	for _, r := range rows {

		if r.Ignored && !showIgnored {

			continue

		}

		if r.RiskTier == "account_inactive" || r.ValidationStatus == "error" {

			out = append(out, r)
			continue

		}

		if s, ok := riskTierSeverity[r.RiskTier]; ok && s >= minSeverity {

			out = append(out, r)

		}

	}

	return out

}