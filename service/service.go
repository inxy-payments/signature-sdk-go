package service

import (
	"github.com/inxy-payments/signature-sdk-go/model"
)

type SignatureService interface {
	SignMessage(message model.Message) (*model.Signature, error)
}
