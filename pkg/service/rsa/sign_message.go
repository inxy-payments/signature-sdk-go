package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/inxy-payments/signature-sdk-go/pkg/model"
)

func (rss *rsaSignatureService) SignMessage(message model.Message) (*model.Signature, error) {
	payload := strings.ToLower(message.Payload) + "_" + strconv.Itoa(int(message.Time))
	hashed := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, rss.privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	return &model.Signature{
		Time:      message.Time,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, nil
}
