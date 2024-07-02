package tests

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inxy-payments/signature-sdk-go/converter"
	"github.com/inxy-payments/signature-sdk-go/model"
	rsaService "github.com/inxy-payments/signature-sdk-go/service/rsa"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

const privateKeyExample = "MIIEowIBAAKCAQEAviXbecnlVp3qPbTAREhr5t8mDTLjJD3cE5SI8LsIjE2wbs23nkCYe47HveFJf+yqD1FqAaDYi+svRsPqVKVD/3HcAkx+Qn1cPQyVmFrbj0Q5U6vP7EuVi4ICG3BX5+l5DCAp5uIcLP9sr9h+4KxaMGaztYzutHjfsZRX99AwLJfw5axVyGIhZb3fZ1YyeI/P2AGQn8iY2XZQGYwc8emyqh3B0zByKLSMuuRDu20jZYXTrWDf+uZDSjZoqcXKmZfJIWxuufICa1H1xIxCxPjV91zG6AKPsqA74TbO91nZGE1yhPE/BA8dkgE+1NEQDWYNMs8cFqQLrLouRqY+g+HVzQIDAQABAoIBADXD+JooR2vFfS1zhYYJQFFouZaz09w0jZ0Pu+Ttzc32TbQXARuDQlp1le8P27uLTM7GA4ZwV6rAln6Y+RJ0JJT/OemAfZcJYWJ1w3rv/fM1pEwPYdx7xs5KtZPSoViXAL43/gEl4DetBat3OPEIavwSni/wqLJpFz9cJb+Ro32H//TECzivHvSxDDUrhMDTQHQeBw7ATiIVNT2iPutprKqjMNga4cg/vxm5BgiMTMjo2adbKQPKa4k5q3YOuFrkacjwbuRBpZtnqWd568moERMym8iHrdsUI/tgprQI7wxev/gj+nk5cbZoEr0fBvoTH/HDna3G5rGOE5uti5adn6ECgYEA6xvoG961ovmZinScEOx/xcrWT2Q1TuazOQesPf0ywfT/BAUCqxVQeEVHV78089HSP5QHHes5iq+MFAL8/hGlPq0EoHDDE1hyxS0gbZcR6oEmRKyOfSbShGn22Cuw0JWt7rOHzdHj8KCpZgpXLJUyKL0Tx2vCKaM3zb7lOFkIshkCgYEAzws06a5LJY4cuKjZkwews0MxCm7SpQXuoSnkOo1ROLukgJ209Le5IdNYC47GYDcwhkuY4tSRxyfq7rd4Upui9XjkaqiblpqOVcdajAI8XgmCbzwxaUcvomQpvC8lFocoOGtAw2P8TZ3WGOb3GoF/o1pQ0Dh9HLOrAPo79RONv9UCgYEA0s7L+SlhPgeF17KlOTuFecldDgSxE9UhwDIUC+Ua/PR7MJR5hwNuiti7ln8YsMJjPaSyGO6QQr0S4eKoC/uwahli+6UAFTmKdyf2Wq1JYDZ7JLqAbNFBk38b2UqbmPuM4GpTi4X2Vw0HtznwXkZMmmCm+nmxt/nkkHPpPfP/KwkCgYBQDphGJ2PdQKcwa/G9XYLgvgFvdEy1DKcp4CXk0hHu6vd/1/tJiOToBG2OAoYIXC7CLucOBn3b0T6RUZYP8yg+3KEN8OZAhMC2wF/ttUucXPb3hgHhIGp1018j6eLgZCCUODyRkM7VQEux01UHBb3R7zFCYiVWfM6JkTiv2gC8hQKBgHHFdpHeTu0vJf480UHd8e0vLfpRPqWhAaZBHRtY05Hv9/ClGR8sZ471e1Nk3LJNmOzzL/HN89oD8gHSJGmqHjmbUwpIQK8zCCpuwzAjbdghaHgupss4TJApnS8HuybW+eGBu/AIUlJqOCCImfoB5Gurk5VsjEpo2+lWIFKEJrlG"

func TestSignMessage(t *testing.T) {
	privateKey, err := converter.ToRSAPrivateKeyFromString(privateKeyExample)
	if err != nil {
		t.Fatal(err)
	}

	timestamp := time.Now().Unix()

	type args struct {
		payload    string
		timestamp  int64
		privateKey *rsa.PrivateKey
	}

	tests := []struct {
		name string
		args args
		want *model.Signature
		err  error
	}{
		{
			name: "success",
			args: args{
				payload:    "TestSignMessage",
				timestamp:  timestamp,
				privateKey: privateKey,
			},
			want: &model.Signature{
				Time: timestamp,
			},
			err: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var signature *model.Signature

			service := rsaService.NewRSASignatureService(tt.args.privateKey)
			message := model.NewMessageWithTimestamp(tt.args.payload, tt.args.timestamp)

			signature, err = service.SignMessage(message)
			if tt.err != nil && err != nil {
				require.Equal(t, tt.err.Error(), err.Error())

				return
			}

			require.Equal(t, tt.want.Time, signature.Time)

			var signedMessageBytes []byte

			signedMessageBytes, err = base64.StdEncoding.DecodeString(signature.Signature)
			if err != nil {
				t.Fatal(err)
			}

			payload := strings.ToLower(tt.args.payload) + "_" + strconv.Itoa(int(tt.args.timestamp))
			hashed := sha256.Sum256([]byte(payload))

			err = rsa.VerifyPKCS1v15(&privateKey.PublicKey, crypto.SHA256, hashed[:], signedMessageBytes)

			assert.NoError(t, err)
		})
	}
}
