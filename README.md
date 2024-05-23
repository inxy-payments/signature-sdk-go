# signature-sdk-go

The `signature-sdk-go` package provides functionality for signing messages using RSA private keys and verifying signatures using the corresponding RSA public keys. This package is useful for ensuring the integrity and authenticity of messages in your Go applications.

## Installation

To use this package, you need to have Go installed. You can download it from [golang.org](https://golang.org/dl/).

To include this package in your project, run:

```sh
go get github.com/inxy-payments/signature-sdk-go
```

## Usage
Below is an example of how to use the signature-sdk-go package to sign a message and verify the signature.

## Example

```go
package main

import (
	"fmt"
	"github.com/inxy-payments/signature-sdk-go/pkg/converter"
	"github.com/inxy-payments/signature-sdk-go/pkg/model"
	rsaSignatureService "github.com/inxy-payments/signature-sdk-go/pkg/service/rsa"
	"log"
)

func main() {
	const privateKeyExample = "MIIEowIBAAKCAQEAviXbecnlVp3qPbTAREhr5t8mDTLjJD3cE5SI8LsIjE2wbs23nkCYe47HveFJf+yqD1FqAaDYi+svRsPqVKVD/3HcAkx+Qn1cPQyVmFrbj0Q5U6vP7EuVi4ICG3BX5+l5DCAp5uIcLP9sr9h+4KxaMGaztYzutHjfsZRX99AwLJfw5axVyGIhZb3fZ1YyeI/P2AGQn8iY2XZQGYwc8emyqh3B0zByKLSMuuRDu20jZYXTrWDf+uZDSjZoqcXKmZfJIWxuufICa1H1xIxCxPjV91zG6AKPsqA74TbO91nZGE1yhPE/BA8dkgE+1NEQDWYNMs8cFqQLrLouRqY+g+HVzQIDAQABAoIBADXD+JooR2vFfS1zhYYJQFFouZaz09w0jZ0Pu+Ttzc32TbQXARuDQlp1le8P27uLTM7GA4ZwV6rAln6Y+RJ0JJT/OemAfZcJYWJ1w3rv/fM1pEwPYdx7xs5KtZPSoViXAL43/gEl4DetBat3OPEIavwSni/wqLJpFz9cJb+Ro32H//TECzivHvSxDDUrhMDTQHQeBw7ATiIVNT2iPutprKqjMNga4cg/vxm5BgiMTMjo2adbKQPKa4k5q3YOuFrkacjwbuRBpZtnqWd568moERMym8iHrdsUI/tgprQI7wxev/gj+nk5cbZoEr0fBvoTH/HDna3G5rGOE5uti5adn6ECgYEA6xvoG961ovmZinScEOx/xcrWT2Q1TuazOQesPf0ywfT/BAUCqxVQeEVHV78089HSP5QHHes5iq+MFAL8/hGlPq0EoHDDE1hyxS0gbZcR6oEmRKyOfSbShGn22Cuw0JWt7rOHzdHj8KCpZgpXLJUyKL0Tx2vCKaM3zb7lOFkIshkCgYEAzws06a5LJY4cuKjZkwews0MxCm7SpQXuoSnkOo1ROLukgJ209Le5IdNYC47GYDcwhkuY4tSRxyfq7rd4Upui9XjkaqiblpqOVcdajAI8XgmCbzwxaUcvomQpvC8lFocoOGtAw2P8TZ3WGOb3GoF/o1pQ0Dh9HLOrAPo79RONv9UCgYEA0s7L+SlhPgeF17KlOTuFecldDgSxE9UhwDIUC+Ua/PR7MJR5hwNuiti7ln8YsMJjPaSyGO6QQr0S4eKoC/uwahli+6UAFTmKdyf2Wq1JYDZ7JLqAbNFBk38b2UqbmPuM4GpTi4X2Vw0HtznwXkZMmmCm+nmxt/nkkHPpPfP/KwkCgYBQDphGJ2PdQKcwa/G9XYLgvgFvdEy1DKcp4CXk0hHu6vd/1/tJiOToBG2OAoYIXC7CLucOBn3b0T6RUZYP8yg+3KEN8OZAhMC2wF/ttUucXPb3hgHhIGp1018j6eLgZCCUODyRkM7VQEux01UHBb3R7zFCYiVWfM6JkTiv2gC8hQKBgHHFdpHeTu0vJf480UHd8e0vLfpRPqWhAaZBHRtY05Hv9/ClGR8sZ471e1Nk3LJNmOzzL/HN89oD8gHSJGmqHjmbUwpIQK8zCCpuwzAjbdghaHgupss4TJApnS8HuybW+eGBu/AIUlJqOCCImfoB5Gurk5VsjEpo2+lWIFKEJrlG"

	privateKey, err := converter.ToRSAPrivateKeyFromString(privateKeyExample)
	if err != nil {
		log.Fatal(err)
	}

	service := rsaSignatureService.NewRSASignatureService(privateKey)
	message := model.NewMessage("test message")

	signature, err := service.SignMessage(message)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(signature.Time)
	fmt.Println(signature.Signature)
}



```