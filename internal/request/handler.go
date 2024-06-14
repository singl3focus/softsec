package request

import (
	"os"
	"fmt"
	"crypto/md5"
	"crypto/rsa"

	"github.com/singl3focus/softsec/internal/license"
	"github.com/singl3focus/softsec/internal/sysinfo"
)

// HandleRSALicenseRequest
func HandleRSALicenseRequest(deviceName string) error {
	privKeyPathPEM := fmt.Sprintf("%s_private.pem", deviceName)
	blkPriv, err := license.ReadPEMFile(privKeyPathPEM, license.BlockTypePrivKey)
	if err != nil {
		return err
	}

	key, err := license.ConvertBlock(blkPriv, license.TypePEMPrivKeyRSA)
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

	decryrtedmsg, err := license.DecryptMsgWithPrivKey(readyKey, ciphermsg)
	if err != nil {
		return err
	}

	sysinfo.DisplayData(decryrtedmsg)

	hash := GenerateHash(decryrtedmsg)
	if ok = license.FileExists(RespLicenseFilename); ok {
		return fmt.Errorf("DANGER: %s already exist", RespLicenseFilename)
	}

	file, err := os.Create(RespLicenseFilename)
	if err != nil {
		return err
	}
	defer file.Close()

	res :=  hash[:]
	_, err = file.Write(res)
	if err != nil {
		return err
	}

	return nil

}

// GenerateHash
func GenerateHash(info []byte) [16]byte {
	salt1 := os.Getenv("SALT1")
	salt2 := os.Getenv("SALT2")

	msg := []byte(salt1)
	msg = append(msg, info...)
	msg = append(msg, []byte(salt2)...)

	return md5.Sum(msg)
}
