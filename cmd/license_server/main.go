package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
	"math/rand"

	"github.com/spf13/viper"

	"github.com/singl3focus/softsec/internal/license"
	"github.com/singl3focus/softsec/internal/request"
)

var (
	defaultValueGenFlag = ""
	genFlag = flag.String("g", defaultValueGenFlag, "Generated keys with specifed name")
	
	defaultValueGenLicRespFlag = ""
	licRespFlag = flag.String("resp", defaultValueGenLicRespFlag, "Reading request file and generate response, flag must be contain name of device")

	defaultValueGenLicReqFlag = ""
	licReqFlag = flag.String("l", defaultValueGenLicReqFlag, "Generate request license file, flag must be contain name of device")
)


func init() {
	// Config setup....	
	setConfig(".", "config", "yaml")
}


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
		pubKeyPathTXT := CreateFilename("txt", "_", *genFlag, "public")
		_, _, err = license.GenerateKeysRSA(pubKeyPathTXT)
		if err != nil {
			log.Fatalf("failed to generate RSA keys: %s", err.Error())
		}
	}
	
	// Give response to license request _______________
	if *licRespFlag != defaultValueGenLicRespFlag {
		err = request.HandleRSALicenseRequest(*licRespFlag)
		if err != nil {
			log.Fatalf("failed to handle message by RSA: %s", err.Error())
		}
	}

	if *licReqFlag != defaultValueGenLicReqFlag {
		err = request.GenerateRSALicenseRequest(*licReqFlag)
		if err != nil {
			log.Fatalf("failed to generate License Request keys: %s", err.Error())
		}
	}

	go func(){
		for {
			request.StartChecking("salt1", "salt2")

			min := 10
			max := 60
			randomDuration := time.Duration(rand.Intn(max - min + 1) + min) * time.Minute
			time.Sleep(randomDuration)
		} 
	}()
}

// setConfig set config
func setConfig(path string, filename string, extension string) {
	viper.SetConfigName(filename)
	viper.SetConfigType(extension)
	viper.AddConfigPath(path)

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("fatal error config file: %s", err.Error())
	}

	log.Printf("Config setup....")
}


// CreateFilename created a filename with specifed format
// Filename consists of the prefix of the main word and the rest of the words separated by a sep passed to the function
func CreateFilename(format, sep string, other ...any) string {
	var res []string
	
	for _, item := range other {
		res = append(res, fmt.Sprint(item))
	}
	
	formatFull := fmt.Sprintf(".%s", format)

	return strings.Join(res, sep) + formatFull
}
