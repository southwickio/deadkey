package main

import (

	"bufio"  //reading plain (non-secret) prompt answers
	"context"  //passed to the one-time live validation call
	"fmt"  //printing prompts and results
	"os"  //stdin/stdout, signal handling
	"os/signal"  //catching Ctrl+C during a masked prompt
	"strings"  //trimming prompt input
	"time"  //stamping firstSeenAt for the one-off risk score

	"github.com/spf13/cobra"
	fuzzyfinder "github.com/ktr0731/go-fuzzyfinder"
	"golang.org/x/term"

	"github.com/southwickio/deadkey/internal/models"
	"github.com/southwickio/deadkey/internal/providers"
	"github.com/southwickio/deadkey/internal/registry"
	"github.com/southwickio/deadkey/internal/risk"
	"github.com/southwickio/deadkey/internal/storage"

)

var (

	addProvider        string
	addSkipValidation  bool

)

var addCmd = &cobra.Command{

	Use:   "add",
	Short: "Manually register a credential that scan can't or won't find",
	Long: `Add lets you manually register a credential. One of the known
providers, or "Other" for anything else. So, it's tracked even though
scan can't discover it automatically`,
	RunE: runAdd,

}

func init() {

	rootCmd.AddCommand(addCmd)

	addCmd.Flags().StringVar(&addProvider, "provider", "", "skip the interactive provider picker")
	addCmd.Flags().BoolVar(&addSkipValidation, "skip-validation", false, "register without an immediate live check")

}

//runAdd requires an interactive terminal throughout: unlike `deadkey scan`,
//there is no non-interactive fallback here, and deliberately so. Per this
//project's rule that a credential's actual value is never accepted as a CLI
//flag/argument (it would leak into shell history and process listings). The
//only safe input path is a masked, interactive prompt. That means `deadkey add`
//cannot be scripted or run from CI; this is a real, stated constraint,
//not an oversight
func runAdd(cmd *cobra.Command, args []string) error {

	if !isInteractive() {

		return fmt.Errorf("deadkey add: requires an interactive terminal (credential values are never accepted as a flag, for the same reason `add` never has a --value option - see this command's source comment)")

	}

	reader := bufio.NewReader(os.Stdin)

	providerName := addProvider
	if providerName == "" {

		var err error
		providerName, err = pickProvider()
		if err != nil {

			return err

		}

	}

	db, err := storage.Open(resolvedConfigDir)
	if err != nil {

		return err

	}
	defer db.Close()

	if providerName == "other" {

		return runAddOther(reader, db)

	}

	return runAddNamedProvider(reader, db, providerName)

}

//pickProvider shows an interactive, type-to-filter fuzzy-find UI (via
//ktr0731/go-fuzzyfinder. Confirmed current, actively maintained, and
//purpose-built for exactly this "pick one item from a list" case, unlike
//heavier full TUI frameworks that would need their own list/filter component
//built on top). go-fuzzyfinder's own documentation confirms Ctrl-C during the
//picker is a normal, internally-handled abort (returns ErrAbort) rather than a
//raw signal that could leave the terminal in a broken state. So, unlike
//readSecret, this needs no separate signal-handling wrapper
//
//"Other" is included as one more entry in the same fuzzy-searchable list, not a
//separate step tacked on afterward
func pickProvider() (string, error) {

	names := append(append([]string{}, registry.Names()...), "Other")

	idx, err := fuzzyfinder.Find(names, func(i int) string {

		return names[i]

	})
	if err != nil {

		if err == fuzzyfinder.ErrAbort {

			return "", fmt.Errorf("deadkey add: cancelled")

		}
		return "", fmt.Errorf("deadkey add: %w", err)

	}

	if names[idx] == "Other" {

		return "other", nil

	}
	return names[idx], nil

}

//runAddOther registers a credential type deadkey has no real provider for.
//Deliberately does not prompt for the credential's value at all: there is no
//API to ever check it against, so storing a value would serve no purpose. This
//is pure bookkeeping; a name and a location description, nothing scored, ever
func runAddOther(reader *bufio.Reader, db *storage.DB) error {

	otherName := readLine(reader, "What is it? (a short name, e.g. \"internal deploy token\")")
	if otherName == "" {

		return fmt.Errorf("deadkey add: a name is required for an \"Other\" entry")

	}

	location := readLine(reader, "Where is it kept? (a free-text description, e.g. \"in the team password manager\")")
	if location == "" {

		location = "manually added (other)"

	}

	cred := models.Credential{

		Provider:            "other",
		Subtype:             models.CredentialSubtype(otherName),
		Location:            location,
		DiscoveryConfidence: models.DiscoveryManual,
		Identifier:          otherName,

	}

	if _, err := storage.UpsertCredential(db, cred); err != nil {

		return err

	}

	fmt.Printf("Registered %q as an \"Other\" credential. It will be tracked but never automatically checked - see `deadkey scan`'s output for where these are listed.\n", otherName)

	return nil

}

//runAddNamedProvider registers a credential for one of deadkey's real
//providers: picks a field set if the provider has more than one, prompts for
//every field (masked and retype-confirmed for secret fields), builds and stores
//the Credential, and, runs one immediate live check using the freshly-entered
//values directly (never via the Credential itself. See
//providers.ManualEntryProvider's doc comment for why that distinction is
//load-bearing, not stylistic)
func runAddNamedProvider(reader *bufio.Reader, db *storage.DB, providerName string) error {

	entryProvider, ok := registry.ManualEntryProviderByName(providerName)
	if !ok {

		return fmt.Errorf("deadkey add: %q does not support manual entry", providerName)

	}

	fieldSets := entryProvider.ManualFieldSets()

	fieldSet := fieldSets[0]
	if len(fieldSets) > 1 {

		labels := make([]string, len(fieldSets))
		for i, fs := range fieldSets {

			labels[i] = fs.Label

		}

		idx, err := fuzzyfinder.Find(labels, func(i int) string {

			return labels[i]

		})
		if err != nil {

			if err == fuzzyfinder.ErrAbort {

				return fmt.Errorf("deadkey add: cancelled")

			}
			return fmt.Errorf("deadkey add: %w", err)

		}
		fieldSet = fieldSets[idx]

	}

	values := make(map[string]string, len(fieldSet.Fields))
	for _, field := range fieldSet.Fields {

		if field.Secret {

			value, err := readSecretConfirmed(field.Label)
			if err != nil {

				return err

			}
			values[field.Key] = value

		} else {

			values[field.Key] = readLine(reader, field.Label)

		}

	}

	cred, err := entryProvider.BuildCredential(fieldSet.Subtype, values)
	if err != nil {

		return err

	}

	credentialID, err := storage.UpsertCredential(db, cred)
	if err != nil {

		return err

	}

	if addSkipValidation {

		fmt.Printf("Registered. Not yet validated - run `deadkey scan` or `deadkey add` again to check it.\n")
		return nil

	}

	return validateAndRecord(db, entryProvider, fieldSet.Subtype, values, providerName, credentialID, cred)

}

//validateAndRecord runs the one-time live check and stores it as its own
//single-credential scan, so it shows up in `deadkey serve`'s history like any
//other check. Deliberately does not call GetActivity or RiskModifiers since
//both would try to re-resolve the secret via the Credential's Metadata the
//normal Discover-based path relies on, which does not exist for a
//manually-entered credential (see providers.ManualEntryProvider's doc comment).
//The resulting assessment honestly reports ActivityUnavailable rather than
//pretending a check that structurally cannot happen did happen
func validateAndRecord(db *storage.DB, entryProvider providers.ManualEntryProvider,
	subtype models.CredentialSubtype, values map[string]string,
	providerName string, credentialID int64, cred models.Credential) error {

	ctx := context.Background()

	validation, err := entryProvider.ValidateManual(ctx, subtype, values)
	if err != nil {

		fmt.Printf("Registered, but the live check itself failed: %v\nThis doesn't necessarily mean the credential is invalid - try `deadkey scan` later.\n", err)
		return nil

	}

	scanID, err := storage.StartScan(db, []string{providerName}, false)
	if err != nil {

		return err

	}

	activity := models.ActivityResult{

		Quality: models.ActivityUnavailable,
		Source:  "manually added credentials have no file or env var to re-check activity against - see `deadkey add`'s documentation",

	}

	var riskAssessment models.RiskAssessment
	switch validation.Status {

	case models.ValidationInvalid:
		riskAssessment = risk.Invalid(validation)
	case models.ValidationAccountInactive:
		riskAssessment = risk.AccountInactive(validation)
	case models.ValidationValid:
		riskAssessment = risk.Score(validation, activity, nil, time.Now())
	default:
		riskAssessment = models.RiskAssessment{Reasoning: fmt.Sprintf("unrecognized validation status %q", validation.Status)}

	}

	assessment := models.CredentialAssessment{

		Credential: cred,
		Validation: validation,
		Activity:   activity,
		Risk:       riskAssessment,

	}

	if err := storage.InsertAssessment(db, scanID, credentialID, assessment, false); err != nil {

		return err

	}
	if err := storage.FinishScan(db, scanID, nil); err != nil {

		return err

	}

	fmt.Printf("Registered and checked: %s\n", riskAssessment.Reasoning)
	fmt.Printf("View it any time with `deadkey serve` (scan #%d).\n", scanID)

	return nil

}

func readLine(reader *bufio.Reader, label string) string {

	fmt.Printf("%s: ", label)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)

}

//readSecretConfirmed prompts for a secret value twice and requires both entries
//to match, since masked input means a typo is otherwise invisible until the
//credential mysteriously doesn't work later
func readSecretConfirmed(label string) (string, error) {

	for attempt := 1; attempt <= 3; attempt++ {

		first, err := readSecret(fmt.Sprintf("%s: ", label))
		if err != nil {

			return "", err

		}
		second, err := readSecret(fmt.Sprintf("%s (again): ", label))
		if err != nil {

			return "", err

		}

		if first == second {

			return first, nil

		}

		fmt.Println("Those didn't match - try again.")

	}

	return "", fmt.Errorf("deadkey add: entries didn't match after 3 attempts")

}

//readSecret reads one masked line of input, protecting against the bug class:
//x/term.ReadPassword restores the terminal's normal (echoing) state via a
//defer, which does not run if the process is killed by a signal (for example:
//Ctrl+C) mid-prompt. Without this, hitting Ctrl+C while typing a masked secret
//leaves the person's terminal silently broken (no visible input) even after
//this program has exited. GetState/Restore exist specifically so a caller can
//guard against this themselves
func readSecret(prompt string) (string, error) {

	fmt.Print(prompt)

	fd := int(os.Stdin.Fd())

	oldState, err := term.GetState(fd)
	if err != nil {

		return "", fmt.Errorf("deadkey add: reading terminal state: %w", err)

	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	defer signal.Stop(sigCh)

	go func() {

		if _, ok := <-sigCh; ok {

			_ = term.Restore(fd, oldState)
			fmt.Println()
			//standard Unix convention: 128 + SIGINT's signal number (2)
			os.Exit(130)

		}

	}()

	b, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {

		return "", fmt.Errorf("deadkey add: reading input: %w", err)

	}

	return string(b), nil

}