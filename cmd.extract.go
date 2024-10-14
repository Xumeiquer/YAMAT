/*
	Copyright © 2020 Jaume Martin
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package main

import (
	"github.com/spf13/cobra"
)

var ExtractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract attachmetns",
	Long:  `Extract command extracts attachemts and save them into disk.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		setGloalState(cmd)
		preLoadEmail(cmd)
		printBanner(cmd)
	},
	Run:     extractCmdFunc,
	PostRun: processOutput,
}

func init() {
	RootCmd.AddCommand(ExtractCmd)

	ExtractCmd.Flags().StringP("name", "", "", "Extract MIME multipartpart based on name")
	ExtractCmd.Flags().StringP("hash", "", "", "Extract MIME multipartpart based on hash (value:yamat dumps the email itself)")
	ExtractCmd.Flags().BoolP("zip", "", false, "Extract and compress MIME multipart with password")
	ExtractCmd.Flags().StringP("zipPass", "", "infected", "Encrypt zip with a password")
}

func extractCmdFunc(cmd *cobra.Command, args []string) {
	zipFile, err := cmd.Flags().GetBool("zip")
	logFatal(err)
	zipPass, err := cmd.Flags().GetString("zipPass")
	logFatal(err)

	hash, err := cmd.Flags().GetString("hash")
	logFatal(err)

	if hash != "" {
		hashFunc(hash, zipFile, zipPass)
	}

	name, err := cmd.Flags().GetString("name")
	logFatal(err)

	if name != "" {
		nameFunc(name, zipFile, zipPass)
	}
}
