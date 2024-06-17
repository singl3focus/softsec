<h1 align="center">Licensed software protection</h1>

<p> <center>
<img src="https://img.shields.io/badge/made_by-singl3focus-blue"> <img src="https://img.shields.io/badge/Open_Source-red" > <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat">
</center> </p>

---

*Project Softsec* provides a user-friendly interface for working with license generation, message encryption and decryption, key generation and other functions to ensure the security of the application usage RSA and ED25519.

# Installation

`go get github.com/singl3focus/softsec` \
`go mod tidy`

## Usage

### Global Usage

Global example of licensing via flags.

```go
package main

import (
	"os"
	"log"
	"flag"
	"time"
	"math/rand"
	"path/filepath"

	"github.com/singl3focus/softsec"
)

var (
	defaultValueGenFlag = ""
	genFlag = flag.String("g", defaultValueGenFlag, "Generated keys with specifed name")
	
	defaultValueGenLicRespFlag = ""
	licRespFlag = flag.String("resp", defaultValueGenLicRespFlag, "Reading request file and generate response, flag must be contain name of device")

	defaultValueGenLicReqFlag = ""
	licReqFlag = flag.String("l", defaultValueGenLicReqFlag, "Generate request license file, flag must be contain name of device")
)


func main() {
	// Log setup _____________________________________
	err := os.MkdirAll("logs", os.ModePerm)
	if err != nil {
		log.Fatalf("failed to create log directory: %v", err)
	}

	today := time.Now().Format("2006-01-02")
	filePath := filepath.Join("logs", "license_app_"+today+".log")

	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil { log.Fatalf("failed to open the log file: %v", err) }
	defer file.Close()

	log.SetOutput(file)
	
	// App setup _____________________________________
    log.Println("Start license app....")
	flag.Parse()

	// Generated keys ________________________________ 
	if *genFlag != defaultValueGenFlag {
		pubKeyPathTXT := softsec.CreateFilename("txt", "_", *genFlag, "public")
		_, _, err = softsec.GenerateKeysRSA(pubKeyPathTXT)
		if err != nil {
			log.Fatalf("failed to generate RSA keys: %s", err.Error())
		}
	}
	
	// Give response to license request ______________
	if *licRespFlag != defaultValueGenLicRespFlag {
        err = softsec.HandleRSALicenseRequest(*licRespFlag)
		if err != nil {
            log.Fatalf("failed to handle message by RSA: %s", err.Error())
		}
	}

    // Generate licemse request ______________________
	if *licReqFlag != defaultValueGenLicReqFlag {
		err = softsec.GenerateRSALicenseRequest(*licReqFlag)
		if err != nil {
			log.Fatalf("failed to generate License Request keys: %s", err.Error())
		}
	}
}

```

**Remember, this is just an example of how you can use it, but it can also be deployed as a server or something else.**

## Support
If you have any difficulties, problems or questions, you can just write to me by e-mail <tursunov.imran@mail.ru> or telegram <https://t.me/single_focus>.

