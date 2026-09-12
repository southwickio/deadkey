package main

import (

	"bufio"  //reading the telemetry prompt's y/n answer
	"context"  //passed to every provider call
	"fmt"  //printing prompts/summaries
	"os"  //stdin/stdout, exit codes, file output
	"path/filepath"  //building the companion CSV filename
	"strings"  //normalizing the telemetry prompt answer, building the companion filename
	"time"  //stamping scan start/end

	"github.com/spf13/cobra"

	"github.com/southwickio/deadkey/internal/config"
	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/output"
	"github.com/southwickio/deadkey/internal/providers"
	"github.com/southwickio/deadkey/internal/registry"
	"github.com/southwickio/deadkey/internal/risk"
	"github.com/southwickio/deadkey/internal/storage"

)

//scan flags. Declared as package-level vars per this file's cobra conventions.
//Bound in init() below
var (

	scanProviders       []string
	scanPaths           []string
	scanPatternMatching bool
	scanJSON            bool
	scanCSV             bool
	scanMinRisk         string
	scanFailOnDead      bool
	scanNoTelemetry     bool
	scanCI              bool
	scanOutput          string
	scanShowIgnored     bool

)

var scanCmd = &cobra.Command{

	Use:   "scan",
	Short: "Scan for credentials and report which look forgotten",
	Long: `Scan discovers credentials across every supported provider, checks
whether each one is still alive, and reports which look safe to revoke`,
	RunE: runScan,

}

func init() {

	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringSliceVar(&scanProviders, "provider", nil, "only scan these providers (default: all)")
	scanCmd.Flags().StringSliceVar(&scanPaths, "path", nil, "override discovery location(s), applied to every active provider")
	scanCmd.Flags().BoolVar(&scanPatternMatching, "pattern-matching", true, "scan .env-style files in addition to structured sources")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "output as JSON")
	scanCmd.Flags().BoolVar(&scanCSV, "csv", false, "output as CSV")
	scanCmd.Flags().StringVar(&scanMinRisk, "min-risk", "", "only show findings at or above this risk tier (dead, rotate, keep)")
	scanCmd.Flags().BoolVar(&scanFailOnDead, "fail-on-dead", false, "exit non-zero if any credential scores \"dead\" (for CI)")
	scanCmd.Flags().BoolVar(&scanNoTelemetry, "no-telemetry", false, "skip telemetry for this run only, without changing the persisted setting")
	scanCmd.Flags().BoolVar(&scanCI, "ci", false, "non-interactive mode: skip prompts, no color")
	scanCmd.Flags().StringVarP(&scanOutput, "output", "o", "", "write results to a file instead of stdout")
	scanCmd.Flags().BoolVar(&scanShowIgnored, "show-ignored", false, "include ignored credentials in the output")

}

//exit codes, named rather than bare numbers so their meaning is visible at
//every call site
const (

	exitClean          = 0
	exitDeadFound      = 1  //only used when --fail-on-dead is set
	exitProviderFailed = 2  //always used, regardless of --fail-on-dead

)

func runScan(cmd *cobra.Command, args []string) error {

	ctx := context.Background()

	cfg, err := config.Load(resolvedConfigDir)
	if err != nil {

		return err

	}

	handleTelemetryFirstRun(cfg)

	db, err := storage.Open(resolvedConfigDir)
	if err != nil {

		return err

	}
	defer db.Close()

	activeProviders, err := registry.Filter(scanProviders)
	if err != nil {

		return err

	}

	discoveryCfg := providers.DiscoveryConfig{

		Paths:           scanPaths,
		PatternMatching: scanPatternMatching,

	}

	requestedNames := make([]string, 0, len(activeProviders))
	for _, p := range activeProviders {

		requestedNames = append(requestedNames, p.Name())

	}

	scanID, err := storage.StartScan(db, requestedNames, scanCI)
	if err != nil {

		return err

	}

	startedAt := time.Now().UTC()
	var providerFailures []models.ProviderFailure

	for _, p := range activeProviders {

		creds, err := p.Discover(ctx, discoveryCfg)
		if err != nil {

			//A provider failing to run at all is reported and skipped, never
			//aborts the rest of the scan
			providerFailures = append(providerFailures, models.ProviderFailure{

				Provider: p.Name(),
				Error:    err.Error(),

			})
			continue

		}

		for _, cred := range creds {

			if err := assessOne(ctx, db, p, cred, scanID); err != nil {

				//A single credential's own processing failing (a storage write
				//error, for instance) is reported inline via a provider-scoped
				//failure note, rather than losing the rest of that provider's
				//results
				providerFailures = append(providerFailures, models.ProviderFailure{

					Provider: p.Name(),
					Error:    fmt.Sprintf("processing %s: %v", cred.Location, err),

				})

			}

		}

	}

	if err := storage.FinishScan(db, scanID, providerFailures); err != nil {

		return err

	}

	rows, err := storage.ListForScan(db, scanID)
	if err != nil {

		return err

	}
	rows = output.FilterByMinRisk(rows, scanMinRisk, scanShowIgnored)

	otherCreds, err := storage.ListOtherCredentials(db)
	if err != nil {

		return err

	}

	report := output.Report{

		ScanID:           scanID,
		StartedAt:        startedAt,
		FinishedAt:       time.Now().UTC(),
		ProvidersChecked: requestedNames,
		ProvidersFailed:  providerFailures,
		Results:          rows,
		OtherCredentials: otherCreds,

	}

	if err := writeReport(report); err != nil {

		return err

	}

	return exitFor(report)

}

//assessOne runs the full Discover-already-done pipeline for a single
//credential: ignore-list check, identity upsert, Validate, GetActivity,
//optional RiskModifiers, and scoring. Every branch always ends in exactly one
//storage.InsertAssessment call, so every discovered credential produces exactly
//one row per scan, regardless of which path it took
func assessOne(ctx context.Context, db *storage.DB, p providers.Provider, cred models.Credential, scanID int64) error {

	ignored, err := storage.IsIgnored(db, cred.Provider, cred.Location)
	if err != nil {

		return err

	}

	credentialID, err := storage.UpsertCredential(db, cred)
	if err != nil {

		return err

	}

	var firstSeenAt time.Time
	if err := db.QueryRow(`SELECT first_seen_at FROM credentials WHERE id = ?`, credentialID).Scan(&firstSeenAt); err != nil {

		firstSeenAt = time.Now().UTC()

	}

	validation, err := p.Validate(ctx, cred)
	if err != nil {

		//The check itself failed (network, rate limit); not evidence about the
		//credential. Recorded as its own outcome, distinct from every
		//models.ValidationStatus value
		assessment := models.CredentialAssessment{

			Credential: cred,
			Validation: models.ValidationResult{Status: models.ValidationError, ErrorDetail: err.Error(), CheckedAt: time.Now()},

		}
		return storage.InsertAssessment(db, scanID, credentialID, assessment, ignored)

	}

	assessment := models.CredentialAssessment{

		Credential: cred,
		Validation: validation,

	}

	switch validation.Status {

	case models.ValidationInvalid:

		assessment.Risk = risk.Invalid(validation)

	case models.ValidationAccountInactive:

		assessment.Risk = risk.AccountInactive(validation)

	case models.ValidationValid:

		activity, err := p.GetActivity(ctx, cred)
		if err != nil {

			//Same reasoning as a Validate error: a failed activity check is not
			//evidence of anything. Fall back to Unavailable so scoring degrades
			//gracefully instead of erroring the whole credential
			activity = models.ActivityResult{Quality: models.ActivityUnavailable, Source: fmt.Sprintf("activity check failed: %v", err)}

		}
		assessment.Activity = activity

		var modifiers []models.RiskModifier
		if rmp, ok := p.(providers.RiskModifierProvider); ok {

			mods, err := rmp.RiskModifiers(ctx, cred)
			if err == nil {

				modifiers = mods

			}
			//A RiskModifiers failure is deliberately non-fatal and silently
			//degrades to "no modifiers". These checks are always optional and
			//best-effort

		}

		assessment.Risk = risk.Score(validation, activity, modifiers, firstSeenAt)

	default:

		//Defensive: an unrecognized ValidationStatus (future addition this
		//orchestrator hasn't been updated for). Never silently scored as if it
		//were Valid
		assessment.Risk = models.RiskAssessment{Reasoning: fmt.Sprintf("unrecognized validation status %q", validation.Status)}

	}

	return storage.InsertAssessment(db, scanID, credentialID, assessment, ignored)

}

//handleTelemetryFirstRun implements the consent model: opt-in, only asked once,
//and never asked at all in a non-interactive context. A blocking stdin prompt
//in a CI runner would hang the job forever rather than fail cleanly.
//scanNoTelemetry only affects this run's storage.InsertAssessment calls are
//unaffected either way, since telemetry is a separate, opt-in feedback
//mechanism; not something scan.go transmits itself
func handleTelemetryFirstRun(cfg *config.Config) {

	if !cfg.IsFirstRun() {

		return

	}

	if scanCI || !isInteractive() {

		cfg.SetTelemetry(false)
		_ = cfg.Save()
		if !quiet {

			fmt.Fprintln(os.Stderr, "deadkey: telemetry is off by default in non-interactive mode. Run `deadkey config telemetry on` to enable anonymous, opt-in risk-feedback telemetry.")

		}
		return

	}

	fmt.Println(`deadkey can optionally send anonymous, opt-in feedback to help improve risk
scoring accuracy across all installs. This never includes credential values,
locations, or anything that could identify your account or machine - see
https://github.com/southwickio/deadkey for exactly what is and isn't sent.

Enable anonymous telemetry? [y/N]`)

	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	optedIn := strings.HasPrefix(strings.ToLower(strings.TrimSpace(answer)), "y")

	cfg.SetTelemetry(optedIn)
	_ = cfg.Save()

}

func isInteractive() bool {

	info, err := os.Stdin.Stat()
	if err != nil {

		return false

	}
	return (info.Mode() & os.ModeCharDevice) != 0

}

func writeReport(r output.Report) error {

	var w = os.Stdout
	if scanOutput != "" {

		f, err := os.Create(scanOutput)
		if err != nil {

			return err

		}
		defer f.Close()

		if scanJSON {

			return output.RenderJSON(f, r)

		}
		if scanCSV {

			if err := output.RenderCSV(f, r); err != nil {

				return err

			}
			return writeOtherCSVCompanion(r)

		}
		//A table doesn't make sense written to a file the way JSON/CSV do.
		//Default to JSON when --output is set without an explicit format
		return output.RenderJSON(f, r)

	}

	if scanJSON {

		return output.RenderJSON(w, r)

	}
	if scanCSV {

		if len(r.OtherCredentials) > 0 {

			fmt.Fprintf(os.Stderr, "Note: %d manually tracked (\"Other\") entries exist but aren't included in CSV written to stdout - use --output to also get a separate companion CSV for them.\n", len(r.OtherCredentials))

		}
		return output.RenderCSV(w, r)

	}

	output.RenderTable(r)
	return nil

}

//writeOtherCSVCompanion writes r.OtherCredentials to a second file alongside
//the main --output CSV, named by inserting "-other" before the file extension
//(for example: "scan.csv" -> "scan-other.csv"). Only written when there's
//actually something to put in it
func writeOtherCSVCompanion(r output.Report) error {

	if len(r.OtherCredentials) == 0 {

		return nil

	}

	ext := filepath.Ext(scanOutput)
	companionPath := strings.TrimSuffix(scanOutput, ext) + "-other" + ext

	f, err := os.Create(companionPath)
	if err != nil {

		return fmt.Errorf("scan: writing companion file for manually tracked entries: %w", err)

	}
	defer f.Close()

	if err := output.RenderOtherCSV(f, r); err != nil {

		return err

	}

	fmt.Printf("Manually tracked (\"Other\") entries written to %s\n", companionPath)
	return nil

}

func exitFor(r output.Report) error {

	if len(r.ProvidersFailed) > 0 {

		os.Exit(exitProviderFailed)

	}

	if scanFailOnDead {

		for _, row := range r.Results {

			if row.RiskTier == "dead" {

				os.Exit(exitDeadFound)

			}

		}

	}

	os.Exit(exitClean)
	return nil

}