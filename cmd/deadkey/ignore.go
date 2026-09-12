package main

import (

	"encoding/json"  //--json output for --list
	"fmt"  //printing results
	"os"  //writing output
	"text/tabwriter"  //aligning the --list table

	"github.com/spf13/cobra"

	"github.com/southwickio/deadkey/internal/storage"

)

var (

	ignoreProvider string
	ignoreReason   string
	ignoreList     bool
	ignoreJSON     bool
	ignoreRemove   string

)

var ignoreCmd = &cobra.Command{

	Use:   "ignore <location>",
	Short: "Stop flagging a specific credential slot",
	Long: `Ignore tells deadkey to stop flagging a credential, keyed by its
location (e.g. "the AWS default profile key") rather than its current value,
so the ignore rule survives credential rotation`,
	RunE: runIgnore,

}

func init() {

	rootCmd.AddCommand(ignoreCmd)

	ignoreCmd.Flags().StringVar(&ignoreProvider, "provider", "", "which provider this credential belongs to (required to add an ignore)")
	ignoreCmd.Flags().StringVar(&ignoreReason, "reason", "", "optional note for why this is ignored")
	ignoreCmd.Flags().BoolVarP(&ignoreList, "list", "l", false, "list everything currently ignored")
	ignoreCmd.Flags().BoolVar(&ignoreJSON, "json", false, "output --list as JSON")
	ignoreCmd.Flags().StringVar(&ignoreRemove, "remove", "", "un-ignore a previously ignored location")

}

func runIgnore(cmd *cobra.Command, args []string) error {

	db, err := storage.Open(resolvedConfigDir)
	if err != nil {

		return err

	}
	defer db.Close()

	switch {

	case ignoreList:

		if len(args) > 0 || ignoreRemove != "" {

			return fmt.Errorf("deadkey ignore: --list cannot be combined with a location or --remove")

		}
		return runIgnoreList(db)

	case ignoreRemove != "":

		if len(args) > 0 {

			return fmt.Errorf("deadkey ignore: cannot specify both a location and --remove - did you mean `deadkey ignore --remove %q`?", args[0])

		}
		return runIgnoreRemove(db)

	case len(args) == 1:

		return runIgnoreAdd(db, args[0])

	default:

		return fmt.Errorf("deadkey ignore: expected exactly one location, or --list, or --remove <location>")

	}

}

//runIgnoreAdd requires --provider explicitly, rather than trying to guess it
//from an existing scan result. This is a real correction from this command's
//original design: storage's ignore_list table is keyed by (provider, location)
//together (see internal/storage/migrations.go), not location alone, and
//auto-resolving the provider by searching past scan results only works for a
//credential that has already been discovered at least once
func runIgnoreAdd(db *storage.DB, location string) error {

	if ignoreProvider == "" {

		return fmt.Errorf("deadkey ignore: --provider is required (ignore_list is keyed by provider AND location together, so this can't be inferred safely)")

	}

	if err := storage.AddIgnore(db, ignoreProvider, location, ignoreReason); err != nil {

		return err

	}

	fmt.Printf("Ignoring %s / %s\n", ignoreProvider, location)
	return nil

}

//runIgnoreRemove reports plainly when nothing was actually removed, rather than
//silently succeeding either way. storage.RemoveIgnore already distinguishes the
//two cases for exactly this reason
func runIgnoreRemove(db *storage.DB) error {

	removed, err := storage.RemoveIgnore(db, ignoreRemove)
	if err != nil {

		return err

	}

	if !removed {

		fmt.Printf("Nothing was ignored at %q.\n", ignoreRemove)
		return nil

	}

	fmt.Printf("No longer ignoring %s\n", ignoreRemove)
	return nil

}

func runIgnoreList(db *storage.DB) error {

	entries, err := storage.ListIgnored(db)
	if err != nil {

		return err

	}

	if ignoreJSON {

		data, err := json.MarshalIndent(entries, "", "  ")
		if err != nil {

			return err

		}
		fmt.Println(string(data))
		return nil

	}

	if len(entries) == 0 {

		fmt.Println("Nothing is currently ignored.")
		return nil

	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROVIDER\tLOCATION\tREASON\tSINCE")
	for _, e := range entries {

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Provider, e.Location, e.Reason, e.CreatedAt.Format("2006-01-02"))

	}
	return w.Flush()

}