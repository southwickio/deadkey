package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var ignoreCmd = &cobra.Command{

	Use:   "ignore",
	Short: "Stop flagging a specific credential slot",
	Long: `Ignore tells deadkey to stop flagging a credential, keyed by its
	location (e.g. "the AWS default profile key") rather than its current value,
	so the ignore rule survives credential rotation`,
	RunE: func(cmd *cobra.Command, args []string) error {

		fmt.Println("deadkey ignore: not yet implemented")
		return nil

	},

}

func init() {

	rootCmd.AddCommand(ignoreCmd)

}
