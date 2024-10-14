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
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/VirusTotal/vt-go"
)

var (
	urlRE = regexp.MustCompile(`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=;])*`)
	ipRE  = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(?::(6553[0-5]|655[0-2]\d|65[0-4]\d{2}|6[0-4]\d{3}|[1-5]\d{4}|[1-9]\d{0,3}))?`)
)

func infoFunc() (data *CommandResult) {
	envelop := GS.Email.Clone()

	data = NewCmdResultWCmd("body", []string{"Attachment"})

	for _, attch := range envelop.Attachments {
		data.Result["Filename"] = attch.FileName
		data.Result["Content-Type"] = attch.ContentType
		data.Result["ContentID"] = attch.ContentID
		data.Result["Modification Date"] = attch.FileModDate.Format("2006-01-02 15:04:05")
		data.Result["Size"] = fmt.Sprintf("%d bytes", len(attch.Content))
		data.Result["MD5"] = getMD5Hash(attch.Content)
		data.Result["SHA1"] = getSHA1Hash(attch.Content)
		data.Result["SHA256"] = getSHA256Hash(attch.Content)
		data.Result["SSDEEP"] = getSSDEEPHash(attch.Content)
	}
	return data
}

func linksFunc() (data *CommandResult) {
	envelop := GS.Email.Clone()

	data = NewCmdResultWCmd("body", []string{"links"})

	textURL := urlRE.FindAllString(envelop.Text, -1)
	htmlURL := urlRE.FindAllString(envelop.HTML, -1)

	for _, url := range textURL {
		data.Result["text"] = url
	}

	for _, url := range htmlURL {
		data.Result["html"] = url
	}
	return data
}

func vtCheckURLFunc() (dataList []*CommandResult) {
	if GS.NetworkAllowed && GS.VTApiKey != "" {
		envelop := GS.Email.Clone()

		dataList = []*CommandResult{}

		client := vt.NewClient(GS.VTApiKey)

		textURL := urlRE.FindAllString(envelop.Text, -1)
		htmlURL := urlRE.FindAllString(envelop.HTML, -1)

		for _, link := range textURL {
			data := NewCmdResultWCmd("body", []string{"vtCheckURL", "text"})

			data.Result["URL"] = link

			urlID := base64.RawURLEncoding.EncodeToString([]byte(link))
			obj, err := client.GetObject(vt.URL("urls/%s", urlID))
			if err != nil {
				data.Result["Error"] = err.Error()
			} else {
				data.Result["Submission Date"] = obj.MustGetTime("first_submission_date").Format("2006-01-02 15:04:05")

				statsI, err := obj.Get("last_analysis_stats")
				if err == nil {
					stats := statsI.(map[string]interface{})
					data.Result["Malicious"] = stats["malicious"]
					data.Result["Suspicious"] = stats["suspicious"]
					data.Result["Undetected"] = stats["undetected"]
					data.Result["Harmless"] = stats["harmless"]
					data.Result["Timeout"] = stats["timeout"]
				}
				data.Result["VT Link"] = fmt.Sprintf("https://www.virustotal.com/gui/url/%s/detection", obj.ID())
			}
			dataList = append(dataList, data)
		}

		for _, link := range htmlURL {
			if !inStrings(link, textURL) {
				data := NewCmdResultWCmd("body", []string{"vtCheckURL", "html"})

				urlID := base64.RawURLEncoding.EncodeToString([]byte(link))
				obj, err := client.GetObject(vt.URL("urls/%s", urlID))
				if err != nil {
					data.Result["Error"] = err.Error()
				} else {
					data.Result["URL"] = link
					data.Result["Submission Date"] = obj.MustGetTime("first_submission_date").Format("2006-01-02 15:04:05")

					statsI, err := obj.Get("last_analysis_stats")
					if err == nil {
						stats := statsI.(map[string]interface{})
						data.Result["Malicious"] = stats["malicious"]
						data.Result["Suspicious"] = stats["suspicious"]
						data.Result["Undetected"] = stats["undetected"]
						data.Result["Harmless"] = stats["harmless"]
						data.Result["Timeout"] = stats["timeout"]
					}
					data.Result["VT Link"] = fmt.Sprintf("https://www.virustotal.com/gui/url/%s/detection", obj.ID())
				}
				dataList = append(dataList, data)
			}
		}
	}
	return dataList
}

func vtCheckFileFunc() (dataList []*CommandResult) {
	if GS.NetworkAllowed && GS.VTApiKey != "" {
		envelop := GS.Email.Clone()

		client := vt.NewClient(GS.VTApiKey)

		for _, attch := range envelop.Attachments {
			data := NewCmdResultWCmd("body", []string{"vtCheckFile", "attachment"})
			sha256 := getSHA256Hash(attch.Content)
			obj, err := client.GetObject(vt.URL("files/%s", sha256))
			if err != nil {
				data.Result["Error"] = err.Error()
			} else {
				data.Result["sha256"] = sha256
				data.Result["Submission Date"] = obj.MustGetTime("first_submission_date").Format("2006-01-02 15:04:05")

				statsI, err := obj.Get("last_analysis_stats")
				if err == nil {
					stats := statsI.(map[string]interface{})
					data.Result["Malicious"] = stats["malicious"]
					data.Result["Suspicious"] = stats["suspicious"]
					data.Result["Undetected"] = stats["undetected"]
					data.Result["Harmless"] = stats["harmless"]
					data.Result["Timeout"] = stats["timeout"]
				}
				data.Result["VT Link"] = fmt.Sprintf("https://www.virustotal.com/gui/file/%s/detection", obj.ID())
			}
			dataList = append(dataList, data)
		}
	}
	return dataList
}
