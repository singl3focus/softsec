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
	
	// Give response to license request _______________
	if *licRespFlag != defaultValueGenLicRespFlag {
		err = softsec.HandleRSALicenseRequest(*licRespFlag)
		if err != nil {
			log.Fatalf("failed to handle message by RSA: %s", err.Error())
		}
	}

	if *licReqFlag != defaultValueGenLicReqFlag {
		err = softsec.GenerateRSALicenseRequest(*licReqFlag)
		if err != nil {
			log.Fatalf("failed to generate License Request keys: %s", err.Error())
		}
	}

	go func(){ // test
		for {
			softsec.StartChecking("salt1", "salt2")

			min := 10
			max := 60
			randomDuration := time.Duration(rand.Intn(max - min + 1) + min) * time.Minute
			time.Sleep(randomDuration)
		} 
	}()
}



