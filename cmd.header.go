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

// HeaderCmd represents the bye command
var HeaderCmd = &cobra.Command{
	Use:   "header",
	Short: "Shows and analyses email headers",
	Long: `Header command does actions around email headers. These headers are a key point
in any security incident handling so this command will help the analust to get the IoC.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		setGloalState(cmd)
		preLoadEmail(cmd)
		printBanner(cmd)
	},
	Run:     headerCmdFunc,
	PostRun: processOutput,
}

func init() {
	RootCmd.AddCommand(HeaderCmd)

	HeaderCmd.Flags().BoolP("envelop", "", false, "Show envelop headers")
	HeaderCmd.Flags().BoolP("headers", "", false, "Show headers")
	HeaderCmd.Flags().BoolP("stdHeaders", "", false, "Show standar mail headers")
	HeaderCmd.Flags().BoolP("noStdHeaders", "", false, "Show non standar mail headers")
	HeaderCmd.Flags().BoolP("spf", "", false, "Check sender")
	HeaderCmd.Flags().BoolP("dkim", "", false, "Check DKIM")
	HeaderCmd.Flags().BoolP("dmarc", "", false, "Check DMARC")
}

func headerCmdFunc(cmd *cobra.Command, args []string) {
	envelop, err := cmd.Flags().GetBool("envelop")
	logFatal(err)

	if envelop {
		res := envelopFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res)
	}

	headers, err := cmd.Flags().GetBool("headers")
	logFatal(err)

	if headers {
		res := headersFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res)
	}

	stdHeaders, err := cmd.Flags().GetBool("stdHeaders")
	logFatal(err)

	if stdHeaders {
		res := stdHeadersFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res)
	}

	noStdHeaders, err := cmd.Flags().GetBool("noStdHeaders")
	logFatal(err)

	if noStdHeaders {
		res := noStdHeadersFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res)
	}

	spf, err := cmd.Flags().GetBool("spf")
	logFatal(err)

	if spf {
		res := spfFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res...)
	}

	dkim, err := cmd.Flags().GetBool("dkim")
	logFatal(err)

	if dkim {
		res := dkimFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res...)
	}

	dmarc, err := cmd.Flags().GetBool("dmarc")
	logFatal(err)

	if dmarc {
		res := dmarcFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res...)
	}
}
