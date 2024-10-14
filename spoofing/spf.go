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
	"net"

	"github.com/jhillyerd/enmime"
)

// ValidHeaders validates the mail authenticity by checking its headers.
// This does not perform any network request and only validated the headers
// among them. This method is not really accurate.
func ValidHeaders(msg *enmime.Envelope) (ok bool, info string) {
	addr := getSenders(msg)

	ok = false
	if addr["From"] == nil {
		info = "No From address!"
	} else if addr["Sender"] != nil && (addr["From"].Address != addr["Sender"].Address) {
		info = "From address is different than Sender"
	} else if addr["Reply-To"] != nil && (addr["From"].Address != addr["Reply-To"].Address) {
		info = "From address is different than Reply-To"
	} else if addr["Return-Path"] != nil && (addr["From"].Address != addr["Return-Path"].Address) {
		info = "From address is different than Return-Path"
	} else {
		var info1 string
		if addr["Sender"] == nil && addr["Reply-To"] == nil && addr["Return-Path"] == nil {
			info1 = "\nNone of Sender, Reply-To and Return-Path is present"
		}
		info = "From address the same as Sender, Reply-To, and Return-Path" + info1
		ok = true
	}
	return
}

// ValidReverseDNS validates the mail authenticity by cheching MX DNS entry.
// This method performs a network request so it can validate sender with its MX
// sender server.
func ValidReverseDNS(msg *enmime.Envelope) (ok bool, info string) {
	addr := getSenders(msg)
	rcvr := getReceived(msg)
	if rcvr == "" {
		ok = false
		info = "Could not find domain or IP in Received by field"
		return
	}
	rcvs := hostOrIPRE.FindAllStringSubmatch(rcvr, -1)
	if len(rcvs) == 0 {
		ok = false
		info = "Could not find domain or IP in Received by field"
	}

	var recvServer string
	if s, valid := addr["Sender"]; valid && s != nil && s.String() != "" {
		hres := hostRE.FindAllStringSubmatch(addr["Sender"].Address, -1)
		if len(hres) == 0 {
			ok = false
			info = "Sender does not match a FQDN"
			return
		}
		recvServer = hres[0][1]
	} else { // Using Form header
		hres := hostRE.FindAllStringSubmatch(addr["From"].Address, -1)
		if len(hres) == 0 {
			ok = false
			info = "Form does not match a FQDN"
			return
		}
		recvServer = hres[0][1]
	}

	mxs, err := net.LookupMX(recvServer)
	if err != nil {
		ok = false
		info = err.Error()
	}

	foundValidMX := false
	for _, mx := range mxs {
		validMX := hostMXRE.FindAllStringSubmatch(mx.Host, -1)
		if len(validMX) == 0 {
			continue
		}
		if recvServer == validMX[0][1] {
			foundValidMX = true
		}
	}

	if foundValidMX {
		ok = true
		info = "Received by domain found in Sender/From MX domains"
	} else {
		ok = false
		info = "Could not match Received by domain to Sender/From MX"
	}

	return
}

// ValidateSPF validates the mail authenticity by cheching MX DNS entry.
// This method performs a network request so it can validate sender with its MX
// sender server.
func ValidateSPF(msg *enmime.Envelope) (ok bool, info string) {
	spfHeader := msg.GetHeader("Received-SPF")
	if len(spfHeader) == 0 {
		ok = false
		info = "No Received-SPF header found"
	}

	spf := spfRE.FindAllStringSubmatch(spfHeader, -1)
	if len(spf) == 0 {
		ok = false
		info = "Unable to process Received-SPF"
		return
	}

	result := spf[0][1]
	if result == "fail" || result == "softfail" {
		ok = false
		info = "Found fail or softfail SPF results"
	} else if result == "none" || result == "neutral" {
		ok = false
		info = "Found none or neutral SPF results"
	} else if result == "permerror" || result == "temperror" {
		ok = false
		info = "Found error condition"
	} else if result == "pass" {
		ok = true
		info = "Found SPF pass result"
	}
	return
}
