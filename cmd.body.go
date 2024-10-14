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

var BodyCmd = &cobra.Command{
	Use:   "body",
	Short: "Anlayse body and attachment data",
	Long: `Body command handles attachments and body itself. It shows information about
the body and email attachmetns. This command can query URLs or hashes against VirusTotal.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		setGloalState(cmd)
		preLoadEmail(cmd)
		printBanner(cmd)
	},
	Run:     bodyCmdFunc,
	PostRun: processOutput,
}

func init() {
	RootCmd.AddCommand(BodyCmd)

	BodyCmd.Flags().BoolP("info", "", false, "Show attachment's information")
	BodyCmd.Flags().BoolP("links", "", false, "Show links when plain text or HTML is used")
	BodyCmd.Flags().BoolP("vtCheckURL", "", false, "Check URL against VirusTotal (This needs vtApikey flag to be issued)")
	BodyCmd.Flags().BoolP("vtCheckFile", "", false, "Check MIME multipart file hash against VirusTotal (This needs vtApikey flag to be issued)")
}

func bodyCmdFunc(cmd *cobra.Command, args []string) {
	info, err := cmd.Flags().GetBool("info")
	logFatal(err)

	if info {
		res := infoFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res)
	}

	links, err := cmd.Flags().GetBool("links")
	logFatal(err)

	if links {
		res := linksFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res)
	}

	vtCheckURL, err := cmd.Flags().GetBool("vtCheckURL")
	logFatal(err)

	if vtCheckURL {
		res := vtCheckURLFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res...)
	}

	vtCheckFile, err := cmd.Flags().GetBool("vtCheckFile")
	logFatal(err)

	if vtCheckFile {
		res := vtCheckFileFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res...)
	}
}
