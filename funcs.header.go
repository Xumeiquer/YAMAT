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
	"io/ioutil"
	"net/mail"
	"os"
	"strings"

	"dev.jau.me/Xumeiquer/YAMAT/spoofing"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
)

const (
	JSONOutpu   = "json"
	TEXTOutput  = "text"
	YAMATOutput = "yamat"
)

var (
	envelopHeaders = []string{"Subject", "To", "From", "Cc", "Bcc", "Date"}
)

func envelopFunc() (data *CommandResult) {
	envelop := GS.Email.Clone()

	data = NewCmdResultWCmd("header", []string{"envelop"})

	for _, k := range envelop.GetHeaderKeys() {
		if inStrings(k, envelopHeaders) {
			val := ""
			for _, vv := range envelop.GetHeaderValues(k) {
				val = val + vv
			}
			data.Result[k] = val

		}
	}
	return data
}

func headersFunc() (data *CommandResult) {
	envelop := GS.Email.Clone()

	data = NewCmdResultWCmd("header", []string{"headers"})

	for _, k := range envelop.GetHeaderKeys() {
		val := ""
		for _, vv := range envelop.GetHeaderValues(k) {
			val = val + vv
		}
		data.Result[k] = val
	}
	return data
}

func stdHeadersFunc() (data *CommandResult) {
	envelop := GS.Email.Clone()

	data = NewCmdResultWCmd("header", []string{"stdHeaders"})

	for _, k := range envelop.GetHeaderKeys() {
		if !strings.HasPrefix(k, "x-") && !strings.HasPrefix(k, "X-") {
			val := ""
			for _, vv := range envelop.GetHeaderValues(k) {
				val = val + vv
			}
			data.Result[k] = val
		}
	}
	return data
}

func noStdHeadersFunc() (data *CommandResult) {
	envelop := GS.Email.Clone()

	data = NewCmdResultWCmd("header", []string{"noStdHeaders"})

	for _, k := range envelop.GetHeaderKeys() {
		if strings.HasPrefix(k, "x-") || strings.HasPrefix(k, "X-") {
			val := ""
			for _, vv := range envelop.GetHeaderValues(k) {
				val = val + vv
			}
			data.Result[k] = val
		}
	}
	return data
}

func spfFunc() (data []*CommandResult) {
	envelop := GS.Email.Clone()

	res := NewCmdResultWCmd("header", []string{"spf", "Technique1"})

	ok, info := spoofing.ValidHeaders(envelop)
	if ok {
		res.Result["PASS"] = info
	} else {
		res.Result["FAIL"] = info
	}

	data = append(data, res)

	res = NewCmdResultWCmd("header", []string{"spf", "Technique2"})
	if GS.NetworkAllowed {
		ok, info = spoofing.ValidReverseDNS(envelop)
		if ok {
			res.Result["PASS"] = info
		} else {
			res.Result["FAIL"] = info
		}

		data = append(data, res)

		res = NewCmdResultWCmd("header", []string{"spf", "Technique3"})
		ok, info = spoofing.ValidateSPF(envelop)
		if ok {
			res.Result["PASS"] = info
		} else {
			res.Result["FAIL"] = info
		}

		data = append(data, res)
	}
	return data
}

func dkimFunc() (data []*CommandResult) {
	if GS.NetworkAllowed {
		tmpfile, err := ioutil.TempFile("", "dkim_check")
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.WriteString(GS.EmailData)
		logFatal(err)

		err = tmpfile.Close()
		logFatal(err)

		r, err := os.Open(tmpfile.Name())
		logFatal(err)

		verifications, err := dkim.Verify(r)
		logFatal(err)

		for _, v := range verifications {
			res := NewCmdResultWCmd("header", []string{"dkim", v.Domain})
			if v.Err == nil {
				res.Result["PASS"] = fmt.Sprintf("valid signature for %s", v.Domain)
			} else {
				res.Result["FAIL"] = fmt.Sprintf("not valid signature for %s", v.Domain)
			}
			data = append(data, res)
		}
	}
	return data
}

func dmarcFunc() (data []*CommandResult) {
	envelop := GS.Email.Clone()

	if GS.NetworkAllowed {
		from := envelop.GetHeader("From")
		addr, err := mail.ParseAddress(from)
		logFatal(err)

		domain := strings.Split(addr.Address, "@")
		res, err := dmarc.Lookup(domain[1])

		cmdRes := NewCmdResultWCmd("header", []string{"dmark", fmt.Sprintf("%s", domain)})

		if err != nil {
			cmdRes.Result["FAIL"] = err.Error()
		} else {
			switch res.DKIMAlignment {
			case dmarc.AlignmentStrict:
				cmdRes.Result["DKIM Alignment"] = res.DKIMAlignment
			case dmarc.AlignmentRelaxed:
				cmdRes.Result["DKIM Alignment"] = res.DKIMAlignment
			default:
				cmdRes.Result["DKIM Alignment"] = "DKIM fail policy not defined"
			}

			switch res.SPFAlignment {
			case dmarc.AlignmentStrict:
				cmdRes.Result["SPF Alignment"] = res.SPFAlignment
			case dmarc.AlignmentRelaxed:
				cmdRes.Result["SPF Alignment"] = res.SPFAlignment
			default:
				cmdRes.Result["SPF Alignment"] = "SPF fail policy not defined"
			}

			switch res.Policy {
			case dmarc.PolicyNone:
				cmdRes.Result["Default Policy"] = res.Policy
			case dmarc.PolicyQuarantine:
				cmdRes.Result["Default Policy"] = res.Policy
			case dmarc.PolicyReject:
				cmdRes.Result["Default Policy"] = res.Policy
			default:
				cmdRes.Result["Default Policy"] = "Not found"
			}

			switch res.SubdomainPolicy {
			case dmarc.PolicyNone:
				cmdRes.Result["Subdomain Policy"] = res.SubdomainPolicy
			case dmarc.PolicyQuarantine:
				cmdRes.Result["Subdomain Policy"] = res.SubdomainPolicy
			case dmarc.PolicyReject:
				cmdRes.Result["Subdomain Policy"] = res.SubdomainPolicy
			default:
				cmdRes.Result["Subdomain Policy"] = "Not found"
			}

			if res.Percent != nil {
				switch {
				case *res.Percent >= 0 && *res.Percent <= 25:
					cmdRes.Result["Mail filtering"] = res.Percent
				case *res.Percent > 25 && *res.Percent <= 50:
					cmdRes.Result["Mail filtering"] = res.Percent
				case *res.Percent > 50 && *res.Percent <= 75:
					cmdRes.Result["Mail filtering"] = res.Percent
				case *res.Percent > 75 && *res.Percent <= 100:
					cmdRes.Result["Mail filtering"] = res.Percent
				}
			} else {
				cmdRes.Result["Mail filtering"] = "nil"
			}
		}
		data = append(data, cmdRes)
	}
	return data
}
