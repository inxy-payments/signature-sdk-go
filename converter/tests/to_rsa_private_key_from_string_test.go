package tests

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"testing"

	"github.com/inxy-payments/signature-sdk-go/converter"

	"github.com/stretchr/testify/assert"
)

const privateKeyExample = "MIIEowIBAAKCAQEAviXbecnlVp3qPbTAREhr5t8mDTLjJD3cE5SI8LsIjE2wbs23nkCYe47HveFJf+yqD1FqAaDYi+svRsPqVKVD/3HcAkx+Qn1cPQyVmFrbj0Q5U6vP7EuVi4ICG3BX5+l5DCAp5uIcLP9sr9h+4KxaMGaztYzutHjfsZRX99AwLJfw5axVyGIhZb3fZ1YyeI/P2AGQn8iY2XZQGYwc8emyqh3B0zByKLSMuuRDu20jZYXTrWDf+uZDSjZoqcXKmZfJIWxuufICa1H1xIxCxPjV91zG6AKPsqA74TbO91nZGE1yhPE/BA8dkgE+1NEQDWYNMs8cFqQLrLouRqY+g+HVzQIDAQABAoIBADXD+JooR2vFfS1zhYYJQFFouZaz09w0jZ0Pu+Ttzc32TbQXARuDQlp1le8P27uLTM7GA4ZwV6rAln6Y+RJ0JJT/OemAfZcJYWJ1w3rv/fM1pEwPYdx7xs5KtZPSoViXAL43/gEl4DetBat3OPEIavwSni/wqLJpFz9cJb+Ro32H//TECzivHvSxDDUrhMDTQHQeBw7ATiIVNT2iPutprKqjMNga4cg/vxm5BgiMTMjo2adbKQPKa4k5q3YOuFrkacjwbuRBpZtnqWd568moERMym8iHrdsUI/tgprQI7wxev/gj+nk5cbZoEr0fBvoTH/HDna3G5rGOE5uti5adn6ECgYEA6xvoG961ovmZinScEOx/xcrWT2Q1TuazOQesPf0ywfT/BAUCqxVQeEVHV78089HSP5QHHes5iq+MFAL8/hGlPq0EoHDDE1hyxS0gbZcR6oEmRKyOfSbShGn22Cuw0JWt7rOHzdHj8KCpZgpXLJUyKL0Tx2vCKaM3zb7lOFkIshkCgYEAzws06a5LJY4cuKjZkwews0MxCm7SpQXuoSnkOo1ROLukgJ209Le5IdNYC47GYDcwhkuY4tSRxyfq7rd4Upui9XjkaqiblpqOVcdajAI8XgmCbzwxaUcvomQpvC8lFocoOGtAw2P8TZ3WGOb3GoF/o1pQ0Dh9HLOrAPo79RONv9UCgYEA0s7L+SlhPgeF17KlOTuFecldDgSxE9UhwDIUC+Ua/PR7MJR5hwNuiti7ln8YsMJjPaSyGO6QQr0S4eKoC/uwahli+6UAFTmKdyf2Wq1JYDZ7JLqAbNFBk38b2UqbmPuM4GpTi4X2Vw0HtznwXkZMmmCm+nmxt/nkkHPpPfP/KwkCgYBQDphGJ2PdQKcwa/G9XYLgvgFvdEy1DKcp4CXk0hHu6vd/1/tJiOToBG2OAoYIXC7CLucOBn3b0T6RUZYP8yg+3KEN8OZAhMC2wF/ttUucXPb3hgHhIGp1018j6eLgZCCUODyRkM7VQEux01UHBb3R7zFCYiVWfM6JkTiv2gC8hQKBgHHFdpHeTu0vJf480UHd8e0vLfpRPqWhAaZBHRtY05Hv9/ClGR8sZ471e1Nk3LJNmOzzL/HN89oD8gHSJGmqHjmbUwpIQK8zCCpuwzAjbdghaHgupss4TJApnS8HuybW+eGBu/AIUlJqOCCImfoB5Gurk5VsjEpo2+lWIFKEJrlG"

func TestToRSAPrivateKeyFromString(t *testing.T) {
	type args struct {
		privateKey string
	}

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKeyExample)
	if err != nil {
		t.Fatal(err)
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(decodedPrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args args
		want *rsa.PrivateKey
		err  error
	}{
		{
			name: "success",
			args: args{
				privateKey: privateKeyExample,
			},
			want: rsaPrivateKey,
			err:  nil,
		},
		{
			name: "fail base64",
			args: args{
				privateKey: "a",
			},
			want: nil,
			err:  base64.CorruptInputError(0),
		},
		{
			name: "fail private key",
			args: args{
				privateKey: base64.StdEncoding.EncodeToString([]byte("test")),
			},
			want: nil,
			err:  asn1.StructuralError{Msg: "tags don't match (16 vs {class:1 tag:20 length:101 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} pkcs1PrivateKey @2"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			privateKey, err := converter.ToRSAPrivateKeyFromString(tt.args.privateKey)

			assert.Equal(t, tt.want, privateKey)
			assert.Equal(t, tt.err, err)

		})
	}
}
