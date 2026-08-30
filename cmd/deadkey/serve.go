package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{

	Use:   "serve",
	Short: "Run the local dashboard",
	Long: `Serve starts a local web dashboard reading from your local scan
	results. No cloud component required`,
	RunE: func(cmd *cobra.Command, args []string) error {

		fmt.Println("deadkey serve: not yet implemented")
		return nil

	},

}

func init() {

	rootCmd.AddCommand(serveCmd)
	
}
