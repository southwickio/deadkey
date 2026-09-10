package main

import (

	"fmt"  //formatting the error message printed on failure
	"os"  //writing to stderr and setting the process exit code

	"github.com/spf13/cobra"  //the CLI framework this whole file builds on

	"github.com/southwickio/deadkey/internal/config"

)

//version is set at build time via -ldflags "-X main.version=...". Left as "dev"
//for local/unreleased builds so `deadkey --version` never silently prints an
//empty string
var version = "dev"

//Shared, resolved state every subcommand can read after root's
//PersistentPreRunE has run. Deliberately simple package-level state rather than
//a dependency-injection framework. Proportionate to a small CLI with a handful
//of commands, matching how cobra itself expects flags to be wired
var (

	configDirFlag string  //raw --config flag value, "" if unset
	quiet         bool
	noColor       bool

	resolvedConfigDir string  //what config.Dir() actually resolved to

)

//rootCmd is the base command. Running `deadkey` with no subcommand shows help;
//every subcommand (scan, add, ignore, serve, config) attaches to this
var rootCmd = &cobra.Command{

	Use:     "deadkey",
	Short:   "Find forgotten API keys before they find you",
	Version: version,
	Long: `deadkey scans your machines and CI runners for credentials, validates
whether they're still alive, and flags which ones are safe to revoke; without
plaintext secrets ever leaving your machine.`,

	//PersistentPreRunE runs before every subcommand's own RunE. It resolves and
	//creates ~/.deadkey (or its Windows/--config equivalent) exactly once,
	//per command invocation, so no individual subcommand has to remember to do
	//this itself. See config.Dir's doc comment for why the Windows default
	//differs from Linux/macOS
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

		dir, err := config.Dir(configDirFlag)
		if err != nil {

			return err

		}

		if err := config.EnsureDir(dir); err != nil {

			return err

		}

		resolvedConfigDir = dir
		return nil

	},

}

func init() {

	rootCmd.PersistentFlags().StringVar(&configDirFlag, "config", "", "config/data directory (default: ~/.deadkey, or %AppData%\\deadkey on Windows)")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-essential output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "disable colored output")

}

//Execute runs the root command. Called from main()
func Execute() {

	if err := rootCmd.Execute(); err != nil {

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)

	}

}