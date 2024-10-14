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
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	zip "github.com/alexmullins/zip"
	"github.com/glaslos/ssdeep"
	"github.com/jhillyerd/enmime"
	"github.com/spf13/cobra"
)

func preLoadEmail(cmd *cobra.Command) {
	var err error
	EmailPath, err := cmd.Flags().GetString("email")
	if EmailPath == "-" {
		GS.EmailPath = EmailPath

		fi, err := os.Stdin.Stat()
		logFatal(err)
		if fi.Mode()&os.ModeNamedPipe == 0 || fi.Size() <= 0 {
			logFatal(ErrNoStdinData)
		} else {
			reader := bufio.NewReader(os.Stdin)
			var output []rune

			for {
				input, _, err := reader.ReadRune()
				if err != nil && err == io.EOF {
					break
				}
				output = append(output, input)
			}
			r := strings.NewReader(string(output))
			tee := io.TeeReader(r, GS.OutFile)
			GS.Email, err = enmime.ReadEnvelope(tee)
			logFatal(err)
		}
	} else {
		if _, err = os.Stat(EmailPath); os.IsNotExist(err) {
			logFatal(err)
		} else {
			r, err := os.Open(EmailPath)
			logFatal(err)
			defer r.Close()

			tee := io.TeeReader(r, GS.OutFile)

			GS.Email, err = enmime.ReadEnvelope(tee)
			logFatal(err)

			r.Seek(0, io.SeekStart)
			rr := bufio.NewReader(r)
			b := make([]byte, 3)
			for {
				n, err := rr.Read(b)
				if n == 0 {
					break
				}
				if err == io.EOF {
					break
				}
				GS.EmailData += string(b[0:n])
			}
		}
	}
}

func setGloalState(cmd *cobra.Command) {
	var err error
	GS.NetworkAllowed, err = cmd.Flags().GetBool("network")
	logFatal(err)

	GS.VTApiKey, err = cmd.Flags().GetString("vtApikey")
	logFatal(err)

	GS.Webhook, err = cmd.Flags().GetString("webhook")
	logFatal(err)

	GS.WebhookKey, err = cmd.Flags().GetString("webhookKey")
	logFatal(err)

	GS.TrustWebhook, err = cmd.Flags().GetBool("trustWebhook")
	logFatal(err)
}

func processOutput(cmd *cobra.Command, args []string) {
	output, err := cmd.Flags().GetString("output")
	logFatal(err)

	GS.OutFilename = ""

	switch output {
	case "json":
		processJSONOutput()
	case "text":
		processTEXTOutput()
	case "raw":
		processRAWOutput()
	case "yamat":
		processYamatOutput()
	default:
		output, err := filepath.Abs(output)
		logFatal(err)
		if _, err := os.Stat(filepath.Dir(output)); !os.IsNotExist(err) {
			if _, err := os.Stat(output); os.IsNotExist(err) {
				GS.OutFilename = output
				err = writeFile(GS.OutFilename, GS.OutFile.Bytes())
				logFatal(err)
			} else {
				fmt.Printf(ErrOutFileExist.Error(), output)
			}
		} else {
			fmt.Printf(ErrDirNotExist.Error(), filepath.Dir(output))
		}
	}
}

func processJSONOutput() {
	var out bytes.Buffer
	b, err := json.Marshal(GS.Output)
	logFatal(err)

	if GS.Webhook != "" {
		if len(GS.Output.CmdRes) > 0 {
			json.Indent(&out, b, "", "\t")
			GS.OutFile.Reset()
			out.WriteTo(GS.OutFile)
		} else {
			out.WriteTo(GS.OutFile)
		}
		processWebHookOutput()
	} else {
		json.Indent(&out, b, "", "\t")
		out.WriteTo(os.Stdout)
	}
}

func processTEXTOutput() {
	out := bytes.NewBuffer(nil)
	for idx, cmd := range GS.Output.CmdRes {
		head, foot := getHeaderText(fmt.Sprintf("%s %s", GS.Output.CmdRes[idx].Command, GS.Output.CmdRes[idx].Args))
		fmt.Fprintf(out, "%s\n\n", head)
		fmt.Fprintf(out, "  >  Command   %s\n", cmd.Command)
		fmt.Fprintf(out, "  >  Args      %v\n", cmd.Args)
		fmt.Fprintf(out, "  >  Timespamt %s\n\n", cmd.Date)
		fmt.Fprintf(out, "%s\n\n", getSepLine("Results"))
		for k, v := range cmd.Result {
			fmt.Fprintf(out, "%s: %s\n", k, v)
		}
		fmt.Fprintf(out, "\n%s\n", foot)
	}

	if GS.Webhook != "" {
		if len(GS.Output.CmdRes) > 0 {
			GS.OutFile.Reset()
			out.WriteTo(GS.OutFile)
		} else {
			out.WriteTo(GS.OutFile)
		}
		processWebHookOutput()
	} else {
		fmt.Print(out.String())
	}
}

func processRAWOutput() {
	out := bytes.NewBuffer(nil)
	for _, cmd := range GS.Output.CmdRes {
		for k, v := range cmd.Result {
			fmt.Fprintf(out, "%s: %s\n", k, v)
		}
	}

	if GS.Webhook != "" {
		if len(GS.Output.CmdRes) > 0 {
			GS.OutFile.Reset()
			out.WriteTo(GS.OutFile)
		} else {
			out.WriteTo(GS.OutFile)
		}
		processWebHookOutput()
	} else {

		fmt.Print(out.String())
	}
}

func processYamatOutput() {
	out := bytes.NewBuffer(nil)

	if GS.Webhook != "" {
		out.WriteTo(GS.OutFile)
		processWebHookOutput()
	} else {
		fmt.Fprintf(out, "%s", GS.OutFile.String())
		fmt.Print(out.String())
	}
}

func processWebHookOutput() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: GS.TrustWebhook},
	}
	req, err := http.NewRequest("POST", GS.Webhook, GS.OutFile)
	logFatal(err)
	if GS.WebhookKey != "" {
		h := strings.SplitN(GS.WebhookKey, ":", 2)
		if len(h) == 2 {
			req.Header.Set(strings.TrimSpace(h[0]), strings.TrimSpace(h[1]))
		}
	}
	req.Header.Set("User-Agent", UserAgent)
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil && err != io.EOF {
		fmt.Println(err.Error())
	} else {
		if resp.StatusCode != 200 {
			fmt.Printf("[ERR] WebHook got %s\n", resp.Status)
		}
	}
}

func printBanner(cmd *cobra.Command) {
	b := `________________________________
\ \ / // \  |  \/  |  / \|_   _|
 \ V // _ \ | |\/| | / _ \ | |
  | |/ ___ \| |  | |/ ___ \| |
  |_/_/   \_|_|  |_/_/   \_|_|
			 
             %s
			 
  Yet Another Mail Analysis Tool
==================================
`
	output, err := cmd.Flags().GetString("output")
	logFatal(err)
	if output == TEXTOutput {
		fmt.Println(fmt.Sprintf(b, Version))
	}
}

func logFatal(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func inStrings(a string, b []string) bool {
	for _, v := range b {
		if a == v {
			return true
		}
	}
	return false
}

func getHeaderText(s string) (string, string) {
	var line, foot string
	pre := "--- %s"
	pos := "%s ---"
	spl := " %s"
	spr := "%s "
	end := ""

	line = fmt.Sprintf("%s%s%s", pre, s, pos)
	for len(line) < 82 {
		line = fmt.Sprintf(line, spl, spr)

	}
	line = fmt.Sprintf(line, end, end)

	for i := 0; i < len(line); i++ {
		foot += "-"
	}

	return fmt.Sprintf("%s\n%s\n%s", foot, line, foot), foot
}

func getSepLine(msg string) string {
	var line string
	spl := "%s-"
	spr := "-%s"
	end := ""

	line = fmt.Sprintf("%s %s %s", spl, msg, spr)

	for len(line) < 82 {
		line = fmt.Sprintf(line, spl, spr)
	}
	return fmt.Sprintf(line, end, end)
}

func getSHA256Hash(b []byte) string {
	return getHash("sha256", b)
}

func getSHA1Hash(b []byte) string {
	return getHash("sha1", b)
}

func getMD5Hash(b []byte) string {
	return getHash("md5", b)
}

func getHash(t string, b []byte) string {
	var h hash.Hash
	switch t {
	case "sha1":
		h = sha1.New()
	case "sha256":
		h = sha256.New()
	case "md5":
		h = md5.New()
	}
	h.Write(b)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getSSDEEPHash(b []byte) string {
	ss := ssdeep.NewSSDEEP()
	h, err := ss.FuzzyByte(b)
	if err != nil {
		return err.Error()
	}
	return h.String()
}

func generateFile(filename string, zipit bool, pass string, data []byte) {
	var err error
	var w io.Writer

	if zipit {
		zipw := zip.NewWriter(GS.OutFile)
		defer zipw.Close()

		if pass != "" {
			w, err = zipw.Encrypt(filepath.Base(filename), pass)
			logFatal(err)
		} else {
			w, err = zipw.Create(filepath.Base(filename))
			logFatal(err)
		}

		_, err = io.Copy(w, bytes.NewReader(data))
		logFatal(err)
		zipw.Flush()
	} else {
		GS.OutFile.Write(data)
	}
}

func writeFile(name string, data []byte) error {
	return ioutil.WriteFile(name, data, 0644)
}
