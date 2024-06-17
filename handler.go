package softsec

import (
	"os"
	"fmt"
	"crypto/md5"
	"crypto/rsa"
)

// HandleRSALicenseRequest
// it is necessary in order to receive encrypted messages with the data of the client's machine
// YOU MUST HAVE .env WITH variables SALT1, SALT2
//
// read only 'deviceName'_private.pem file 
func HandleRSALicenseRequest(deviceName, salt1, salt2 string) error {
	privKeyPathPEM := fmt.Sprintf("%s_private.pem", deviceName)
	blkPriv, err := ReadPEMFile(privKeyPathPEM, BlockTypePrivKey)
	if err != nil {
		return err
	}

	key, err := ConvertBlock(blkPriv, TypePEMPrivKeyRSA)
	if err != nil {
		return err
	}

	readyKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("failed to convert data block to needed type")
	}

	ciphermsg, err := GetInfoFromFile(ReqLicenseFilename)
	if err != nil {
		return err
	}

	decryrtedmsg, err := DecryptMsgWithPrivKey(readyKey, ciphermsg)
	if err != nil {
		return err
	}

	DisplayData(decryrtedmsg, "CLIENT MACHINE INFO: ")

	hash := GenerateHash(decryrtedmsg, salt1, salt2)

	if ok = FileExists(RespLicenseFilename); ok {
		return fmt.Errorf("DANGER: %s already exist", RespLicenseFilename)
	}

	file, err := os.Create(RespLicenseFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(hash)
	if err != nil {
		return err
	}

	return nil

}

// GenerateHash return hash of needed info with salt1 and salt2
func GenerateHash(info []byte, salt1, salt2 string) []byte {
	msg := []byte(salt1)
	msg = append(msg, info...)
	msg = append(msg, []byte(salt2)...)

	hash := md5.Sum(msg)
	return hash[:]
}
