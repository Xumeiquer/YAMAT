```txt
________________________________
\ \ / // \  |  \/  |  / \|_   _|
 \ V // _ \ | |\/| | / _ \ | |
  | |/ ___ \| |  | |/ ___ \| |
  |_/_/   \_|_|  |_/_/   \_|_|

  Yet Another Mail Analysis Tool
==================================
```

# Yet Another Mail Analysis Tool

There several tools to analyze email headers and body, some of them analyses the headers, other does body analysis by extracting indicator of compromise. But, there is not a tool that do all in one. YAMAT pretents to be the tool that includes all that a cybersecurity analyst needs when analysing emails.

## Features

* Extract IoC
* Show envelop headers
* Show standard headers
* Show non-standard headers
* Show attachment information
* Show body text and HTML versions
* Check URL and attachment with VirusTotal
* Extract attachment
* Extract URL from body
* Several output formats
* It is possible to send results to a webhook
* It is possible to chain several YAMAT executions

## How to use YAMAT

YAMAT is a command line tool so it usage is really easy. It works with commands, there are some commands to do a specific tasks and there are a global flags for quick results.

### Examples

Getting quick IoC for blocking in Firewall/Proxy
```sh
./yamat --email scam.eml --ioc
{
	"Results": [
		{
			"Command": "root",
			"Args": [
				"ioc"
			],
			"Date": "2020-01-11T23:59:48.547667+01:00",
			"Result": {
				"From": "\"Mrs Robin R. Sanders\"\u003cpeirce@maine.edu\u003e",
				"Return-Path": "\u003cpeirce@maine.edu\u003e",
				"Subject": "PAYMENT NOTIFICATION"
			}
		}
	]
}
```

As you can image the default output format is **json**, but you can change that by using the `--output` flag.

```sh
./yamat --email ../../YAMAT.bak/example/custom/eml/scam.eml --ioc --output text
________________________________
\ \ / // \  |  \/  |  / \|_   _|
 \ V // _ \ | |\/| | / _ \ | |
  | |/ ___ \| |  | |/ ___ \| |
  |_/_/   \_|_|  |_/_/   \_|_|

             v0.1.0-dev

  Yet Another Mail Analysis Tool
==================================

------------------------------------------------------------------------------
---                               root [ioc]                               ---
------------------------------------------------------------------------------

  >  Command   root
  >  Args      [ioc]
  >  Timespamt 2020-01-12 00:05:34.49656 +0100 CET m=+0.016071158

----------------------------------- Results -----------------------------------

Subject: PAYMENT NOTIFICATION
From: "Mrs Robin R. Sanders"<peirce@maine.edu>
Return-Path: <peirce@maine.edu>

------------------------------------------------------------------------------
```

If you want to analyze the header you will need to use `header` command. The following example checks the **SPF**.

```sh
 ./yamat --email spam.eml header --spf
{
	"Results": [
		{
			"Command": "header",
			"Args": [
				"spf",
				"T1"
			],
			"Date": "2020-01-12T00:39:41.058466+01:00",
			"Result": {
				"PASS": "From address the same as Sender, Reply-To, and Return-Path\nNone of Sender, Reply-To and Return-Path is present"
			}
		}
	]
}
```

As you may see, there is one result and it is beacuse only one technique was use. There are two more techniques, but they need Internet connectivity. You can allow Internet connectivity by issuing `--network` flag.

```sh
./yamat --email spam.eml --network header --spf
{
	"Results": [
		{
			"Command": "header",
			"Args": [
				"spf",
				"T1"
			],
			"Date": "2020-01-12T00:40:54.527456+01:00",
			"Result": {
				"PASS": "From address the same as Sender, Reply-To, and Return-Path\nNone of Sender, Reply-To and Return-Path is present"
			}
		},
		{
			"Command": "header",
			"Args": [
				"spf",
				"T2"
			],
			"Date": "2020-01-12T00:40:54.527495+01:00",
			"Result": {
				"FAIL": "Could not find domain or IP in Received by field"
			}
		},
		{
			"Command": "header",
			"Args": [
				"spf",
				"T3"
			],
			"Date": "2020-01-12T00:40:54.527565+01:00",
			"Result": {
				"PASS": "Found SPF pass result"
			}
		}
	]
}
```

You are able to send any result to a WebHook. This functionality is really interesting because you can integrate YAMAT with a SIEM o DataBase, for example. The format will be json as defult fromat, but you can use any other avaliable formats.

```sh
./yamat --email spam.eml --network header --spf --webhook "http://localhost:3000"
```

Finally it is worth to mention that you can check `hash` or `URL` againt VirusTotal. **YAMAT does not upload any information to VT**, YAMAT only checks or search for.

```sh
./yamat --email spam.eml --network --vtApikey <VT APIKey> body --vtCheckFile a73c3edfbd59f8e679e8b169efcf806e759671e0
{
	"Results": [
		{
			"Command": "body",
			"Args": [
				"vtCheckFile",
				"attachment"
			],
			"Date": "2020-01-12T23:48:50.17847+01:00",
			"Result": {
				"Error": "File \"7026a1a86bd838260f55cb2fb0cb4cfe68ad449fc53a8e073a56db2f1a61a99c\" not found"
			}
		}
	]
}
```


### Main help message

```txt
YAMAT pretends to be the tool that any cybersecurity analyst needs for
his/her daily job. YAMAT understands eml and msg formats and performs header
analysis, header evaluation, and spoofing checks. YAMAT is capable of extracting
attachments as well as forwarded emails.

Usage:
  yamat [flags]
  yamat [command]

Available Commands:
  body        Anlayse body and attachment data
  extract     Extract attachmetns
  header      Shows and analyses email headers
  help        Help about any command
  version     Print YAMAT's version

Flags:
      --config string       config file (default is $HOME/.yamat.yml)
  -e, --email string        email to be analyzed
  -h, --help                help for yamat
      --ioc                 show IoC, helpful for a quick assessment
      --network             allow to perfor network queries
      --output string       output format [ json | text | raw | yamat ] (default "json")
      --trustWebhook        verify https certificate
      --vtApikey string     virusTotal API key (This needs network flag to be issued)
      --webhook string      defines the webhook where data will be forwarded, eg. https://localhost:1234
      --webhookKey string   defines the webhook header and api token, eg. X-API-Token:abc123

Use "yamat [command] --help" for more information about a command.
```

#### Body command help message

```txt
Body command handles attachments and body itself. It shows information about
the body and email attachmetns. This command can query URLs or hashes against VirusTotal.

Usage:
  yamat body [flags]

Flags:
  -h, --help          help for body
      --info          Show attachment's information
      --links         Show links when plain text or HTML is used
      --vtCheckFile   Check MIME multipart file hash against VirusTotal (This needs vtApikey flag to be issued)
      --vtCheckURL    Check URL against VirusTotal (This needs vtApikey flag to be issued)

Global Flags:
      --config string       config file (default is $HOME/.yamat.yml)
  -e, --email string        email to be analyzed
      --network             allow to perfor network queries
      --output string       output format [ json | text | raw | yamat ] (default "json")
      --trustWebhook        verify https certificate
      --vtApikey string     virusTotal API key (This needs network flag to be issued)
      --webhook string      defines the webhook where data will be forwarded, eg. https://localhost:1234
      --webhookKey string   defines the webhook header and api token, eg. X-API-Token:abc123
```

#### Header command help message

```txt
Header command does actions around email headers. These headers are a key point
in any security incident handling so this command will help the analust to get the IoC.

Usage:
  yamat header [flags]

Flags:
      --dkim           Check DKIM
      --dmarc          Check DMARC
      --envelop        Show envelop headers
      --headers        Show headers
  -h, --help           help for header
      --noStdHeaders   Show non standar mail headers
      --spf            Check sender
      --stdHeaders     Show standar mail headers

Global Flags:
      --config string       config file (default is $HOME/.yamat.yml)
  -e, --email string        email to be analyzed
      --network             allow to perfor network queries
      --output string       output format [ json | text | raw | yamat ] (default "json")
      --trustWebhook        verify https certificate
      --vtApikey string     virusTotal API key (This needs network flag to be issued)
      --webhook string      defines the webhook where data will be forwarded, eg. https://localhost:1234
      --webhookKey string   defines the webhook header and api token, eg. X-API-Token:abc123
```

#### Extract command help message

```txt
Extract command extracts attachemts and save them into disk.

Usage:
  yamat extract [flags]

Flags:
      --hash string      Extract MIME multipartpart based on hash (value:yamat dumps the email itself)
  -h, --help             help for extract
      --name string      Extract MIME multipartpart based on name
      --zip              Extract and compress MIME multipart with password
      --zipPass string   Encrypt zip with a password (default "infected")

Global Flags:
      --config string       config file (default is $HOME/.yamat.yml)
  -e, --email string        email to be analyzed
      --network             allow to perfor network queries
      --output string       output format [ json | text | raw | yamat ] (default "json")
      --trustWebhook        verify https certificate
      --vtApikey string     virusTotal API key (This needs network flag to be issued)
      --webhook string      defines the webhook where data will be forwarded, eg. https://localhost:1234
      --webhookKey string   defines the webhook header and api token, eg. X-API-Token:abc123
```
