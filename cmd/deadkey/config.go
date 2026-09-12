package main

import (

	"bufio"  //reading the reset confirmation answer
	"encoding/json"  //--json output for show/defaults show
	"fmt"  //printing everything else
	"os"  //stdin for the reset confirmation, stdout
	"strings"  //normalizing the reset confirmation answer

	"github.com/spf13/cobra"

	"github.com/southwickio/deadkey/internal/config"
	"github.com/southwickio/deadkey/internal/registry"

)

var (

	configShowJSON      bool
	defaultsShowJSON    bool
	defaultsSetProviders []string
	defaultsSetPaths     []string
	defaultsClearProviders bool
	defaultsClearPaths     bool
	resetYes            bool

)

//configCmd is the parent command. Running `deadkey config` with no subcommand
//defaults to `config show`
var configCmd = &cobra.Command{

	Use:   "config",
	Short: "View or change deadkey settings",
	RunE:  runConfigShow,

}

var configShowCmd = &cobra.Command{

	Use:   "show",
	Short: "Show all current settings",
	RunE:  runConfigShow,

}

var configPathCmd = &cobra.Command{

	Use:   "path",
	Short: "Print the resolved config/data directory",
	RunE: func(cmd *cobra.Command, args []string) error {

		fmt.Println(resolvedConfigDir)
		return nil

	},

}

var configResetCmd = &cobra.Command{

	Use:   "reset",
	Short: "Erase all local settings (telemetry status, defaults) - not scan history",
	RunE:  runConfigReset,

}

var configTelemetryCmd = &cobra.Command{

	Use:   "telemetry",
	Short: "View or change telemetry opt-in status",

}

var configTelemetryOnCmd = &cobra.Command{

	Use:   "on",
	Short: "Opt in to anonymous, opt-in telemetry",
	RunE: func(cmd *cobra.Command, args []string) error {

		return setTelemetry(true)

	},

}

var configTelemetryOffCmd = &cobra.Command{

	Use:   "off",
	Short: "Opt out of telemetry",
	RunE: func(cmd *cobra.Command, args []string) error {

		return setTelemetry(false)

	},

}

var configTelemetryStatusCmd = &cobra.Command{

	Use:   "status",
	Short: "Show current telemetry status",
	RunE:  runConfigTelemetryStatus,

}

var configDefaultsCmd = &cobra.Command{

	Use:   "defaults",
	Short: "View or change persisted CLI defaults (--provider, --path)",
}

var configDefaultsShowCmd = &cobra.Command{

	Use:   "show",
	Short: "Show current defaults",
	RunE:  runConfigDefaultsShow,

}

var configDefaultsSetCmd = &cobra.Command{

	Use:   "set",
	Short: "Set persisted default providers and/or paths",
	Long: `Set only touches the fields whose flag was actually passed - running
"config defaults set --provider aws" does not affect an existing --path
default. Each flag that IS passed fully replaces that field (this is not
additive - running it twice with different providers gives you the second
list, not the union). To clear one field without touching the other, use
--clear-providers or --clear-paths; to clear both, use "config defaults
clear"`,
	RunE: runConfigDefaultsSet,

}

var configDefaultsClearCmd = &cobra.Command{

	Use:   "clear",
	Short: "Clear both default providers and default paths",
	RunE: func(cmd *cobra.Command, args []string) error {

		cfg, err := config.Load(resolvedConfigDir)
		if err != nil {

			return err

		}
		cfg.Defaults.Providers = nil
		cfg.Defaults.Paths = nil
		if err := cfg.Save(); err != nil {

			return err

		}
		fmt.Println("Defaults cleared.")
		return nil

	},

}

func init() {

	rootCmd.AddCommand(configCmd)

	configShowCmd.Flags().BoolVar(&configShowJSON, "json", false, "output as JSON")
	configCmd.Flags().BoolVar(&configShowJSON, "json", false, "output as JSON")

	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configPathCmd)
	configCmd.AddCommand(configResetCmd)
	configResetCmd.Flags().BoolVarP(&resetYes, "yes", "y", false, "skip the confirmation prompt")

	configCmd.AddCommand(configTelemetryCmd)
	configTelemetryCmd.AddCommand(configTelemetryOnCmd)
	configTelemetryCmd.AddCommand(configTelemetryOffCmd)
	configTelemetryCmd.AddCommand(configTelemetryStatusCmd)

	configCmd.AddCommand(configDefaultsCmd)
	configDefaultsCmd.AddCommand(configDefaultsShowCmd)
	configDefaultsShowCmd.Flags().BoolVar(&defaultsShowJSON, "json", false, "output as JSON")

	configDefaultsCmd.AddCommand(configDefaultsSetCmd)
	configDefaultsSetCmd.Flags().StringSliceVar(&defaultsSetProviders, "provider", nil, "default provider(s) for `deadkey scan`")
	configDefaultsSetCmd.Flags().StringSliceVar(&defaultsSetPaths, "path", nil, "default discovery path(s) for `deadkey scan`")
	configDefaultsSetCmd.Flags().BoolVar(&defaultsClearProviders, "clear-providers", false, "clear the default providers, leaving default paths untouched")
	configDefaultsSetCmd.Flags().BoolVar(&defaultsClearPaths, "clear-paths", false, "clear the default paths, leaving default providers untouched")

	configCmd.AddCommand(configDefaultsClearCmd)

}

//configShowOutput is a display-only shape for `config show`. config.Config
//itself deliberately doesn't serialize its resolved directory (path is a
//private field, set at Load time from wherever the file actually was), so this
//wraps the real Config with that one extra piece of context
type configShowOutput struct {

	ConfigVersion int              `json:"config_version"`
	ConfigDir     string           `json:"config_dir"`
	Telemetry     config.Telemetry `json:"telemetry"`
	Defaults      config.Defaults  `json:"defaults"`

}

func runConfigShow(cmd *cobra.Command, args []string) error {

	cfg, err := config.Load(resolvedConfigDir)
	if err != nil {

		return err

	}

	out := configShowOutput{

		ConfigVersion: cfg.ConfigVersion,
		ConfigDir:     resolvedConfigDir,
		Telemetry:     cfg.Telemetry,
		Defaults:      cfg.Defaults,

	}

	if configShowJSON {

		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {

			return err

		}
		fmt.Println(string(data))
		return nil

	}

	fmt.Printf("Config directory: %s\n\n", out.ConfigDir)
	printTelemetryStatus(cfg)
	fmt.Println()
	printDefaults(cfg)

	return nil

}

func runConfigReset(cmd *cobra.Command, args []string) error {

	if !resetYes {

		fmt.Print("This will erase all local settings (telemetry status, persisted defaults) - your scan history is not affected. Continue? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {

			fmt.Println("Cancelled.")
			return nil

		}

	}

	if err := config.Reset(resolvedConfigDir); err != nil {

		return err

	}

	fmt.Println("Settings reset.")
	return nil

}

func setTelemetry(optedIn bool) error {

	cfg, err := config.Load(resolvedConfigDir)
	if err != nil {

		return err

	}

	cfg.SetTelemetry(optedIn)
	if err := cfg.Save(); err != nil {

		return err

	}

	if optedIn {

		fmt.Println("Telemetry is now on.")

	} else {

		fmt.Println("Telemetry is now off.")

	}
	return nil

}

func runConfigTelemetryStatus(cmd *cobra.Command, args []string) error {

	cfg, err := config.Load(resolvedConfigDir)
	if err != nil {

		return err

	}

	printTelemetryStatus(cfg)
	return nil

}

func printTelemetryStatus(cfg *config.Config) {

	if cfg.IsFirstRun() {

		fmt.Println("Telemetry: off (never asked)")
		return

	}

	if cfg.Telemetry.OptedIn {

		fmt.Printf("Telemetry: on (since %s, install id: %s)\n",
			cfg.Telemetry.AskedAt.Format("2006-01-02"), cfg.Telemetry.InstallID)

	} else {

		fmt.Printf("Telemetry: off (declined %s)\n", cfg.Telemetry.AskedAt.Format("2006-01-02"))

	}

}

func runConfigDefaultsShow(cmd *cobra.Command, args []string) error {

	cfg, err := config.Load(resolvedConfigDir)
	if err != nil {

		return err

	}

	if defaultsShowJSON {

		data, err := json.MarshalIndent(cfg.Defaults, "", "  ")
		if err != nil {

			return err

		}
		fmt.Println(string(data))
		return nil

	}

	printDefaults(cfg)
	return nil

}

func printDefaults(cfg *config.Config) {

	if len(cfg.Defaults.Providers) == 0 {

		fmt.Println("Default providers: none set")

	} else {

		fmt.Printf("Default providers: %s\n", strings.Join(cfg.Defaults.Providers, ", "))

	}

	if len(cfg.Defaults.Paths) == 0 {

		fmt.Println("Default paths: none set")

	} else {

		fmt.Printf("Default paths: %s\n", strings.Join(cfg.Defaults.Paths, ", "))

	}

}

//runConfigDefaultsSet implements the replace-per-field semantics documented
//on configDefaultsSetCmd's Long text; merges new fields on top of existing
//values, not new list items into an existing field.
//--clear-providers/--clear-paths exist specifically because a StringSlice flag
//has no unambiguous way to represent "clear this list" versus "one empty-string
//entry"
func runConfigDefaultsSet(cmd *cobra.Command, args []string) error {

	if defaultsClearProviders && cmd.Flags().Changed("provider") {

		return fmt.Errorf("deadkey config defaults set: --clear-providers and --provider cannot be used together")

	}
	if defaultsClearPaths && cmd.Flags().Changed("path") {

		return fmt.Errorf("deadkey config defaults set: --clear-paths and --path cannot be used together")

	}

	touchedProviders := cmd.Flags().Changed("provider") || defaultsClearProviders
	touchedPaths := cmd.Flags().Changed("path") || defaultsClearPaths

	if !touchedProviders && !touchedPaths {

		return fmt.Errorf("deadkey config defaults set: nothing to set - specify --provider, --path, --clear-providers, and/or --clear-paths")

	}

	if cmd.Flags().Changed("provider") {

		//Fail fast: validate against the real provider registry now, rather
		//than storing a typo that only surfaces as a confusing error the next
		//time `deadkey scan` runs
		if _, err := registry.Filter(defaultsSetProviders); err != nil {

			return fmt.Errorf("deadkey config defaults set: %w", err)

		}

	}

	cfg, err := config.Load(resolvedConfigDir)
	if err != nil {

		return err

	}

	if defaultsClearProviders {

		cfg.Defaults.Providers = nil

	} else if cmd.Flags().Changed("provider") {

		cfg.Defaults.Providers = defaultsSetProviders

	}

	if defaultsClearPaths {

		cfg.Defaults.Paths = nil

	} else if cmd.Flags().Changed("path") {

		cfg.Defaults.Paths = defaultsSetPaths

	}

	if err := cfg.Save(); err != nil {

		return err

	}

	printDefaults(cfg)
	return nil

}