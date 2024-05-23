package converter

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
)

func ToRSAPrivateKeyFromString(privateKey string) (*rsa.PrivateKey, error) {
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(decodedPrivateKey)
	if err != nil {
		return nil, err
	}

	return rsaPrivateKey, nil
}
