/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/HashMapsData2Value/algoring/pkg/ring_bn254"
	"github.com/spf13/cobra"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a keypair.",
	Long:  `Generates a BN254 secret key and public key that can be used for ring signatures.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("keygen called")
	},
}

func init() {
	rootCmd.AddCommand(keygenCmd)

	sk, pk := ring_bn254.KeyGen()
	fmt.Println("Secret key:", sk)
	fmt.Println("Public key:", pk)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keygenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// keygenCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
