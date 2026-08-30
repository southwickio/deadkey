package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

//rootCmd is the base command. Running `deadkey` with no subcommand shows help;
//every subcommand (scan, add, ignore, serve) attaches to this
var rootCmd = &cobra.Command{

	Use:   "deadkey",
	Short: "Find forgotten API keys before they find you",
	Long: `deadkey scans your machines and CI runners for credentials, validates
whether they're still alive, and flags which ones are safe to revoke; without
plaintext secrets ever leaving your machine.`,

}

//Execute runs the root command. Called from main()
func Execute() {

	if err := rootCmd.Execute(); err != nil {

		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)

	}

}