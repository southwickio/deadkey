package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	
	Use:   "scan",
	Short: "Scan for credentials and report which look forgotten",
	Long: `Scan discovers credentials across every supported provider, checks
whether each one is still alive, and reports which look safe to revoke`,
	RunE: func(cmd *cobra.Command, args []string) error {

		fmt.Println("deadkey scan: not yet implemented")
		return nil

	},

}

func init() {

	rootCmd.AddCommand(scanCmd)

}