package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var addCmd = &cobra.Command{

	Use:   "add",
	Short: "Manually register a credential that scan can't or won't find",
	Long: `Add lets you manually register a credential. One of the known
	providers, or "Other" for anything else. So, it's tracked even though
	scan can't discover it automatically`,
	RunE: func(cmd *cobra.Command, args []string) error {
	
		fmt.Println("deadkey add: not yet implemented")
		return nil
	
	},

}

func init() {

	rootCmd.AddCommand(addCmd)

}
