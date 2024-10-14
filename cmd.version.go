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
	"runtime"

	"github.com/spf13/cobra"
)

// VersionCmd represents the hello command
var VersionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print YAMAT's version",
	Run: func(cmd *cobra.Command, args []string) {
		if Version != "" {
			fmt.Printf("YAMAT %s\n", Version)
			if BuildHash != "" && BuildTime != "" {
				fmt.Printf("Build timestamp: %s\nCommit: %s\n", BuildTime, BuildHash)
			}
			fmt.Printf("Go version: %s\nGo compiler: %s\nPlatform: %s/%s\n", runtime.Version(), runtime.Compiler, runtime.GOOS, runtime.GOARCH)
		} else {
			fmt.Println("YAMAT v0.0.0 -- Dev build")
		}
	},
}

func init() {
	RootCmd.AddCommand(VersionCmd)
}
