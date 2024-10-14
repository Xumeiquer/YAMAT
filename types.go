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
	"bytes"
	"time"

	"github.com/jhillyerd/enmime"
)

// GlobalState represents the global variables as well as the results
type GlobalState struct {
	EmailPath      string           `json:"-"`
	Email          *enmime.Envelope `json:"-"`
	EmailData      string           `json:"-"`
	NetworkAllowed bool             `json:"-"`
	VTApiKey       string           `json:"-"`
	OutFilename    string           `json:"-"`
	OutFile        *bytes.Buffer    `json:"-"`
	Webhook        string           `json:"-"`
	WebhookKey     string           `json:"-"`
	TrustWebhook   bool             `json:"-"`

	Output *Result
}

func NewGlobalState() *GlobalState {
	return &GlobalState{
		OutFile: &bytes.Buffer{},
		Output:  NewResult(),
	}
}

type Result struct {
	CmdRes []*CommandResult `json:"Results"`
}

func NewResult() (r *Result) {
	return &Result{}
}

func NewResultWCmd(cmd string, args []string) (r *Result) {
	r = &Result{}
	r.CmdRes = append(r.CmdRes, NewCmdResultWCmd(cmd, args))
	return r
}

type CommandResult struct {
	Command string
	Args    []string
	Date    time.Time
	Result  map[string]interface{}
}

func NewCmdResult() (r *CommandResult) {
	r = &CommandResult{
		Date:   time.Now(),
		Result: make(map[string]interface{}),
	}
	return r
}

func NewCmdResultWCmd(cmd string, args []string) (r *CommandResult) {
	r = &CommandResult{
		Command: cmd,
		Args:    args,
		Date:    time.Now(),
		Result:  make(map[string]interface{}),
	}
	return r
}
