package softsec

import (
	"crypto/md5"
	"crypto/rsa"
)

func EncryptMsgWithPubKey(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	encryptedMsg, err := rsa.EncryptOAEP(md5.New(), reader, pub, msg, nil)
	if err != nil {
		return nil, err
	}

	return encryptedMsg, nil
}

func DecryptMsgWithPrivKey(priv *rsa.PrivateKey, ciphermsg []byte) ([]byte, error) {
	decryptedMsg, err := rsa.DecryptOAEP(md5.New(), reader, priv, ciphermsg, nil)
	if err != nil {
		return nil, err
	}

	return decryptedMsg, nil
}