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
)

func hashFunc(hash string, zip bool, zipPass string) {
	envelop := GS.Email.Clone()
	if hash == "yamat" {
		// Email data is already in GS.FileOut
		return
	}
	if GS.OutFilename == "" {
		for _, attch := range envelop.Attachments {
			md5 := getMD5Hash(attch.Content)
			sha1 := getSHA1Hash(attch.Content)
			sha256 := getSHA256Hash(attch.Content)
			if md5 == hash || sha1 == hash || sha256 == hash {
				generateFile(attch.FileName, zip, zipPass, attch.Content)
			}
		}
	} else {
		fmt.Println(ErrNotOutputFile.Error())
	}
}

func nameFunc(name string, zip bool, zipPass string) {
	envelop := GS.Email.Clone()
	if GS.OutFilename == "" {
		for _, attch := range envelop.Attachments {
			if name == attch.FileName {
				generateFile(attch.FileName, zip, zipPass, attch.Content)
			}
		}
	} else {
		fmt.Println(ErrNotOutputFile.Error())
	}
}
