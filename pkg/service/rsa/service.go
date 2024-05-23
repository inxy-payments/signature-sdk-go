package rsa

import (
	"crypto/rsa"

	"github.com/inxy-payments/signature-sdk-go/pkg/service"
)

type rsaSignatureService struct {
	privateKey *rsa.PrivateKey
}

func NewRSASignatureService(privateKey *rsa.PrivateKey) service.SignatureService {
	return &rsaSignatureService{privateKey: privateKey}
}
