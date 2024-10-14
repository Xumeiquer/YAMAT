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
	"fmt"
	"os"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "yamat",
	Short: "YAMAT stands for Yet Another Mail Analysis Tool",
	Long: `YAMAT pretends to be the tool that any cybersecurity analyst needs for
his/her daily job. YAMAT understands eml and msg formats and performs header
analysis, header evaluation, and spoofing checks. YAMAT is capable of extracting
attachments as well as forwarded emails.`,
	PreRun: func(cmd *cobra.Command, args []string) {
		setGloalState(cmd)
		preLoadEmail(cmd)
		printBanner(cmd)
	},
	Run:     rootCmdFunc,
	PostRun: processOutput,
}

// cmdExecute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func cmdExecute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.Flags().BoolP("ioc", "", false, "show IoC, helpful for a quick assessment")
	RootCmd.PersistentFlags().StringP("email", "e", "", "email to be analyzed")
	RootCmd.PersistentFlags().StringP("output", "", "json", "output format [ json | text | raw | yamat ]")
	RootCmd.PersistentFlags().StringP("webhook", "", "", "defines the webhook where data will be forwarded, eg. https://localhost:1234")
	RootCmd.PersistentFlags().StringP("webhookKey", "", "", "defines the webhook header and api token, eg. X-API-Token:abc123")
	RootCmd.PersistentFlags().BoolP("trustWebhook", "", false, "verify https certificate")
	RootCmd.PersistentFlags().BoolP("network", "", false, "allow to perfor network queries")
	RootCmd.PersistentFlags().StringP("vtApikey", "", "", "virusTotal API key (This needs network flag to be issued)")
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.yamat.yml)")
	RootCmd.MarkFlagRequired("email")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".yamat" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".yamat")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

func rootCmdFunc(cmd *cobra.Command, args []string) {
	ioc, err := cmd.Flags().GetBool("ioc")
	logFatal(err)

	if ioc {
		res := iocFunc()
		GS.Output.CmdRes = append(GS.Output.CmdRes, res)
	}
}
