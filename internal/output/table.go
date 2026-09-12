package output

import (

	"fmt"  //building formatted output
	"os"  //writing to stdout
	"text/tabwriter"  //aligning table columns

	"github.com/southwickio/deadkey/internal/storage"

)

//RenderTable prints r as a human-readable, grouped table: Dead, Rotate, Keep,
//Account Inactive, then Couldn't Check. Ignored rows only appear if they were
//already included in r.Results (see FilterByMinRisk's showIgnored parameter).
//This function doesn't re-filter, it just groups and prints whatever it's given
func RenderTable(r Report) {

	fmt.Printf("deadkey scan #%d - %d provider(s) checked\n\n", r.ScanID, len(r.ProvidersChecked))

	if len(r.ProvidersFailed) > 0 {

		fmt.Println("Providers that could not be checked at all:")
		for _, f := range r.ProvidersFailed {

			fmt.Printf("  - %s: %s\n", f.Provider, f.Error)

		}
		fmt.Println()

	}

	groups := []struct {

		title  string
		filter func(storage.AssessmentRow) bool

	}{

		{"DEAD - safe to revoke", func(a storage.AssessmentRow) bool { return a.RiskTier == "dead" }},
		{"ROTATE - still in use, worth rotating", func(a storage.AssessmentRow) bool { return a.RiskTier == "rotate" }},
		{"KEEP - no action needed", func(a storage.AssessmentRow) bool { return a.RiskTier == "keep" }},
		{"ACCOUNT INACTIVE - unrelated to age/usage", func(a storage.AssessmentRow) bool { return a.RiskTier == "account_inactive" }},
		{"COULD NOT CHECK", func(a storage.AssessmentRow) bool { return a.ValidationStatus == "error" }},

	}

	found := false

	for _, g := range groups {

		var rows []storage.AssessmentRow
		for _, a := range r.Results {

			if g.filter(a) {

				rows = append(rows, a)

			}

		}
		if len(rows) == 0 {

			continue

		}

		found = true
		fmt.Printf("%s (%d)\n", g.title, len(rows))

		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, a := range rows {

			ignoredMark := ""
			if a.Ignored {

				ignoredMark = " [ignored]"

			}
			fmt.Fprintf(w, "  %s\t%s\t%s%s\n", a.Provider, a.Location, a.RiskReasoning, ignoredMark)

		}
		w.Flush()
		fmt.Println()

	}

	if !found {

		fmt.Println("No credentials found by any checked provider.")

	}

	if len(r.OtherCredentials) > 0 {

		fmt.Printf("MANUALLY TRACKED (not scanned - no real API exists to check these) (%d)\n", len(r.OtherCredentials))
		w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, o := range r.OtherCredentials {

			fmt.Fprintf(w, "  %s\t%s\n", o.OtherName, o.Location)

		}
		w.Flush()

	}

}