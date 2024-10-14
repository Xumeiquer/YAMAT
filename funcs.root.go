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

import "fmt"

func iocFunc() (data *CommandResult) {
	envelop := GS.Email.Clone()

	data = NewCmdResultWCmd("root", []string{"ioc"})

	for _, h := range []string{"Subject", "From", "To", "Cc", "Bcc", "Return-Path"} {
		if envelop.GetHeader(h) != "" {
			data.Result[h] = envelop.GetHeader(h)
		}
	}

	for idx, u := range urlRE.FindAllString(envelop.Text, -1) {
		if envelop.GetHeader(u) != "" {
			data.Result[fmt.Sprintf("URL (text) - %d", idx)] = envelop.GetHeader(u)
		}
	}
	for idx, u := range urlRE.FindAllString(envelop.HTML, -1) {
		if envelop.GetHeader(u) != "" {
			data.Result[fmt.Sprintf("URL (html) - %d", idx)] = envelop.GetHeader(u)
		}
	}
	for idx, u := range ipRE.FindAllString(envelop.Text, -1) {
		if envelop.GetHeader(u) != "" {
			data.Result[fmt.Sprintf("IP (text) - %d", idx)] = envelop.GetHeader(u)
		}
	}
	for idx, u := range ipRE.FindAllString(envelop.HTML, -1) {
		if envelop.GetHeader(u) != "" {
			data.Result[fmt.Sprintf("IP (html) - %d", idx)] = envelop.GetHeader(u)
		}
	}

	return data
}
