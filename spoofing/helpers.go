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

package spoofing

import (
	"net/mail"
	"regexp"
	"strings"

	"github.com/jhillyerd/enmime"
)

var (
	headers     = []string{"Sender", "From", "Reply-To", "Return-Path"}
	rcvServerRE = regexp.MustCompile(`by\s+(\S*?)(?:\s+\(.*?\))?\s+with`)
	hostOrIPRE  = regexp.MustCompile(`(\w+\.\w+|\d+\.\d+\.\d+\.\d+)$`)
	hostRE      = regexp.MustCompile(`(\w+\.\w+)$`)
	hostMXRE    = regexp.MustCompile(`(\w+\.\w+).$`)
	spfRE       = regexp.MustCompile(`\s*(\w+)\s+\((.*?):\s*(.*?)\)\s+(.*);`)
)

func getSenders(msg *enmime.Envelope) (addr map[string]*mail.Address) {
	addr = map[string]*mail.Address{}

	for _, ad := range headers {
		addL, err := msg.AddressList(ad)
		if err != nil {
			addr[ad] = nil
		}
		for _, a := range addL {
			addr[ad] = a
		}
	}
	return
}

func getReceived(msg *enmime.Envelope) (received string) {
	received = ""
	var rcvHeaders []string
	// Could be more than one header with the same name filed
	// so all of them needs to be catched, otherwise only the
	// first one will be reported
	for _, header := range []string{"Received", "X-Received"} {
		rcvHeaders = append(rcvHeaders, msg.GetHeader(header))
	}

	// Extracting server from all collected headers
	md := map[string][]string{}
	for _, header := range rcvHeaders {
		re := regexp.MustCompile(`by\s+(?P<server>\S*?)(?:\s+\(.*?\))?\s+with`)
		names := re.SubexpNames()
		allRes := re.FindAllStringSubmatch(header, -1)

		var res []string
		if len(allRes) > 0 {
			res = allRes[0]
		}

		for i, n := range res {
			md[names[i]] = append(md[names[i]], n)
		}
	}

	for _, v := range md["server"] {
		if strings.Contains(v, ":") {
			// TODO: handle IPv6
			// Avoid IPv6 for now
			continue
		} else {
			received = v
			break
		}
	}

	return
}
