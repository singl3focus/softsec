package request

import (
	"crypto/md5"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"reflect"

	"github.com/singl3focus/softsec/internal/license"
	"github.com/singl3focus/softsec/internal/sysinfo"
)

const (
	ReqLicenseFilename  = "./license.req"
	RespLicenseFilename = "./license.resp"
)

func StartChecking(s1, s2 string) {
	hash1, err := CheckLicense(s1, s2)
	if err != nil {
		log.Fatal(err.Error())
	}
	hash2, err := GetInfoFromFile(RespLicenseFilename)
	if err != nil {
		log.Fatal(err.Error())
	}

	if !reflect.DeepEqual(hash1, hash2) {
		os.Exit(1)
	}
}

// GenerateRSALicenseRequest
func GenerateRSALicenseRequest(deviceName string) error {
	machineInfo, err := sysinfo.GetFullMachineInfo()
	if err != nil { return err }

	pubKeyPathPEM := fmt.Sprintf("%s_public.pem", deviceName)
	blkPub, err := license.ReadPEMFile(pubKeyPathPEM, license.BlockTypePubKey)
	if err != nil { return err }

	key, err := license.ConvertBlock(blkPub, license.TypePEMPubKeyRSA)
	if err != nil { return err }

	readyKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to convert data block to needed type")
	}

	request, err := license.EncryptMsgWithPubKey(readyKey, machineInfo)
	if err != nil { return err }

	file, err := os.Create(ReqLicenseFilename)
	if err != nil { return err }
	defer file.Close()

	_, err = file.Write(request)
	if err != nil { return err }

	return nil
}

// GetInfoFromFile
func GetInfoFromFile(LicenseFilename string) ([]byte, error) {
	license, err := os.ReadFile(LicenseFilename)
	if err != nil {
		return nil, err
	}

	return []byte(license), nil
}

// CheckLicense
func CheckLicense(salt1, salt2 string) ([]byte, error) {
	machineInfo, err := sysinfo.GetFullMachineInfo()
	if err != nil {
		return []byte{}, err
	}

	msg := []byte(salt1) // put here your salt, it must match the salt on the server
	msg = append(msg, machineInfo...)
	msg = append(msg, []byte(salt2)...) // put here your salt, it must match the salt on the server

	hash := md5.Sum(msg)
	return hash[:], nil
}