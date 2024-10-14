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

var (
	// Version YAMAT version
	Version string
	// BuildHash commit hash
	BuildHash string
	// BuildTime commit timestamp
	BuildTime string

	// GS is YAMAT global state
	GS *GlobalState

	// UserAgent yamat's user-agent
	UserAgent = "YAMAT/1.0"
)

func main() {
	GS = NewGlobalState()
	cmdExecute()
}
