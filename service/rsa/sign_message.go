package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"

	model2 "github.com/inxy-payments/signature-sdk-go/model"
)

func (rss *rsaSignatureService) SignMessage(message model2.Message) (*model2.Signature, error) {
	payload := strings.ToLower(message.Payload) + "_" + strconv.Itoa(int(message.Time))
	hashed := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rss.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return &model2.Signature{
		Time:      message.Time,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}
