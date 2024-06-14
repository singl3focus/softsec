package license

import (
	"os"
	"log"
	"fmt"
	"strings"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

var (
	reader = rand.Reader
	bitSize = 2048

	TypePEMPrivKeyEd25519 = "Ed25519PrivKey"
	TypePEMPubKeyEd25519 = "Ed25519PubKey"
	TypePEMPrivKeyRSA = "RSAPrivKey"
	TypePEMPubKeyRSA = "RSAPubKey"

	BlockTypePubKey = "PUBLIC KEY"
	BlockTypePrivKey = "PRIVATE KEY"
)

// GenetateKeysEd25519 generate Pub and Priv keys by ed25519 (for bi-directional communicate with pairs keys)
// the keys are automaticly saved in root directory of the project
func GenetateKeysEd25519(prefix, pubKeyPathTXT string) error {
	privKeyPathTXT := strings.Replace(pubKeyPathTXT, "public", "private", 1)

	if (FileExists(pubKeyPathTXT) && FileExists(privKeyPathTXT)) {
		return fmt.Errorf("instanse Ed25519 keys with prefix %s files already saved", prefix)
	}
	if (FileExists(pubKeyPathTXT) || FileExists(privKeyPathTXT)) {
		return fmt.Errorf("programs should store two keys in two files, not one")
	}

	pubK, privK, err :=  ed25519.GenerateKey(rand.Reader)
	if err != nil { return err }
	
	err = saveKey(privKeyPathTXT, pubK)
	if err != nil { return err }

	err = saveKey(pubKeyPathTXT, privK)
	if err != nil { return err }

	log.Println("Save files with Ed25519 keys has been successfull....")
	return nil
}


// GenerateKeysRSA generate Pub and Priv keys by RSA (for broadcast communication with pub key)
// the keys are saved in root directory of the project
func GenerateKeysRSA(pubKeyPathTXT string) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKeyPathTXT := strings.Replace(pubKeyPathTXT, "public", "private", 1)
	pubKeyPathPEM := strings.Replace(pubKeyPathTXT, "txt", "pem", 1)
	privKeyPathPEMtemp := strings.Replace(pubKeyPathTXT, "public", "private", 1)
	privKeyPathPEM := strings.Replace(privKeyPathPEMtemp, "txt", "pem", 1)

	if (FileExists(pubKeyPathTXT) && FileExists(privKeyPathTXT) && FileExists(privKeyPathPEM) && FileExists(pubKeyPathPEM)) {
		return nil,nil, fmt.Errorf("instanse RSA keys files already saved")
	} else if (FileExists(pubKeyPathTXT) || FileExists(privKeyPathTXT) && FileExists(privKeyPathPEM) && FileExists(pubKeyPathPEM)) {
		return nil,nil, fmt.Errorf("programs should store two keys in two files, not one")
	}

	privKey, err := rsa.GenerateKey(reader, bitSize)
	if err != nil { return nil,nil, err }

	pubKey := privKey.PublicKey
	
	err = saveKey(privKeyPathTXT, privKey)
	if err != nil { return nil,nil, err }
	err = savePrivatePEMKey(privKeyPathPEM, privKey)
	if err != nil { return nil,nil, err }

	err = saveKey(pubKeyPathTXT, &pubKey)
	if err != nil { return nil,nil, err }
	err = savePublicPEMKey(pubKeyPathPEM, &pubKey)
	if err != nil { return nil,nil, err }

	log.Println("Save files with RSA keys has been successfull....")
	return privKey, &pubKey, nil
}


func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
	 	return false
	}
	return !info.IsDir()
}

// saveKey saving key in the format specified in the arg "filePath".
// Recommend use .txt format.
func saveKey(filePath string, key interface{}) error {
	var data []byte

	switch val := key.(type) {
	case *rsa.PublicKey:
		data = x509.MarshalPKCS1PublicKey(val)
	case *rsa.PrivateKey:
		data = x509.MarshalPKCS1PrivateKey(val)
	case ed25519.PrivateKey:
		data = val
	case ed25519.PublicKey:
		data = val
	default:
		return fmt.Errorf("unknown key type for save")
	}
	
	if len(data) > 1 {
		os.WriteFile(filePath, data, 0666)
	}

	return nil
}

func savePrivatePEMKey(fileName string, privKey *rsa.PrivateKey) error {
	var privateKey = &pem.Block{
		Type:  BlockTypePrivKey,
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}

	outFile, err := os.Create(fileName)
	if err != nil { return err }
	defer outFile.Close()

	err = pem.Encode(outFile, privateKey)
	if err != nil { return err }

	return nil
}

func savePublicPEMKey(fileName string, pubkey *rsa.PublicKey) error {
	keyBytes := x509.MarshalPKCS1PublicKey(pubkey)

	var pemkey = &pem.Block{
		Type:  BlockTypePubKey,
		Bytes: keyBytes,
	}

	pemfile, err := os.Create(fileName)
	if err != nil { return err }
	defer pemfile.Close()

	err = pem.Encode(pemfile, pemkey)
	if err != nil { return err }

	return nil
}