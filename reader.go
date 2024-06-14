package softsec

import (
	"os"
	"fmt"
	"crypto/x509"
	"encoding/pem"
)

// ReadPEMFile read .pem file, return pointer to pem.Block and err
// param::filePath is the specified path to the desired file
// param::blockType can be "PUBLIC KEY", "PRIVATE KEY", another name may cause an error
//
// For full read PEM file 
func ReadPEMFile(filePath, blockType string) (*pem.Block, error) {
	PEMData, err := os.ReadFile(filePath)
	if err != nil { return nil, err }
	
	block, _ := pem.Decode(PEMData)
	if block == nil || block.Type != blockType {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
		
	return block, nil
}


// ConvertBlock convert block to specifed path, return a needed key and err 
// param::dataType can be one of the variables in the generate file
func ConvertBlock(block *pem.Block, dataType string) (any, error) {
	var key any
	var err error

	switch dataType {
	case TypePEMPrivKeyEd25519:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes) // return only different types of priv key
	case TypePEMPrivKeyRSA:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes) // return only *rsa.PrivateKey
	case TypePEMPubKeyEd25519:
		key, err = x509.ParsePKIXPublicKey(block.Bytes) // returns different types of pub key
	case TypePEMPubKeyRSA:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes) // returns only *rsa.PublicKey
	default:
		return nil, fmt.Errorf("unknown dataType for convert block. Receive: %s", dataType)
	}

	if err != nil {
		return nil, err
	}

	return key, nil
}