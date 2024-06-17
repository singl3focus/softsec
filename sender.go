package softsec

import (
	"os"
	"fmt"
	"log"
	"reflect"
	"crypto/md5"
	"crypto/rsa"
)

const (
	ReqLicenseFilename  = "./license.req"
	RespLicenseFilename = "./license.resp"
)

// StartChecking
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
// read only 'deviceName'_public.pem file
func GenerateRSALicenseRequest(deviceName string) error {
	machineInfo, err := GetFullMachineInfo()
	if err != nil { return err }

	pubKeyPathPEM := fmt.Sprintf("%s_public.pem", deviceName)
	blkPub, err := ReadPEMFile(pubKeyPathPEM, BlockTypePubKey)
	if err != nil { return err }

	key, err := ConvertBlock(blkPub, TypePEMPubKeyRSA)
	if err != nil { return err }

	readyKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to convert data block to needed type")
	}

	request, err := EncryptMsgWithPubKey(readyKey, machineInfo)
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
	machineInfo, err := GetFullMachineInfo()
	if err != nil {
		return []byte{}, err
	}

	msg := []byte(salt1) // it must match the salt on the your checker(server)
	msg = append(msg, machineInfo...)
	msg = append(msg, []byte(salt2)...) // it must match the salt on the your checker(server)

	hash := md5.Sum(msg)
	return hash[:], nil
}