package tests

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/inxy-payments/signature-sdk-go/converter"
	"github.com/stretchr/testify/assert"
)

const privateKeyPEMExample = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAvX6Wm+p8XrIUgGjEgZsaLYh8vdmFWwnwNMo6/DA3bWNQ7HNm
Eelp5tcq7y9hk0uRQ9lvBztMrBhslVQkZuX/jBYgW/JW9NOvgGrGyf9XAIZaOycx
KgwmbyOPGo1Ra9XzhB5eIxTgpPrhkinGFOlUFNYK555KD40O6rfo53t/FgJjPMiK
XlOaZTpjcVDFDSEe8TGwbijfp2aF+QoLuybhncwCp7FNcYfce21TFd1B5M51pCbg
JdebVqSIdr7ZEB3vpznNvilE/dIrG7IiEQ0B6EiZCpI/NNCaZaqO9TLc+yHoALnM
lrqwcpcJpNeRahDuffiFsBRNxAfo50gW7uwEXwIDAQABAoIBAQCfeRNi7/nu78uV
LZaCxHdJbp4cYB18umZu5uqxJhrfcj++Xne+B0Paw6YcWTGy9luwUCLCYUNrabqo
CYIBHvrreAuPlelcbXI7jqDxinQ7utXhBmC31DXcPn7Gh7vIFuyzeaMbvww3i/Oe
QI21N5BNYL0Yo/wMDlhJbLETbrlLWQ+/5ab/KMOiYOOo9VEcXkJFq3432s9ZY0hP
0CXsElmFduMPrag1JmM3MlWK941CJoS8ZsFQExduckO02J08rGIk6LGAsv7qFdgq
w3T854Z7xBV4bGvhAj12hlDn5cM1QFkQ0+FDhjAOSZBl64QyvMjO1lwJjIS+moDX
3zWwVdlRAoGBAOkJJfRJ83fPXPd1BBMoVKtEL7gfU0hE9aJafAZkQRAbABjSjPjX
vMG1IGQwDTwCPMvRGaxqj4dZ9VvgIuqUi/bFY9e0SpM0+g3z86ju07ln+5sP0jsh
R9cLsuHm3n6O/a1FczDd0U9fPi7SPBwJ57+3fc1BJGj52tOXnBXUMhCDAoGBANAr
A42n8zZ7qmR3iZd5uvWjt2Y7bYpxZwNorGyahhouDJrZb8i1wrYCLbhQ+xrUPwfI
nqanCIJ8ZK01s4whrwil7ZWsbIYAHLu+sF+Q/MA/RR+jPSHSbmpcL+poL9Wv3SDy
abwwJXO7fl1WDmt6ifOr7J64Nxy+ORRfM8fsMT31AoGAZD6rNQsa0M9DDrAnsJYI
1iPe4zWWfeAsSkriT12RH3x97i+ktOcZK7re1DpXdxj/Ti4E/UZZt7/a7Ereukps
axs+d+v2qJyBdL8cce9K5Nb2RR3pMcZ/QOKncMX/sDGSrpbRlpPVFm/CMCH/+Y/J
QY+Nbl43a3EP0TXGzx0Y7EECgYEAsztFzPK9QrzJYcVWb1h9M8ApSVmDoD6xrkqy
orONIP9jFPR//bUZl7JagScgfOIf/uiqSNzqQ8csu8HP/KiH1w9ed49ExT9VfgTa
QP5J0JDpSCs5mGRhcyw6iT35aagI4bQ2e7SMmo/lZiGROtL/8hCmI6aCtTnHVZX+
tHTVlP0CgYARf+URMh/IBiFsIswIJkTgQb/6MF5DE9pLY/whxHl5e3r5jvvMkAud
W3ebwKfYrUr9WFj1vCQb15a8gIsTfDMySDnDY3Ss/2NZbwOQc0WHfRdyuHWT1KRp
DqfKLy/Bkj65TJeAf7gsO87kcO4pPgAgQU+Xfg2Xf87V/WonWJYCsw==
-----END RSA PRIVATE KEY-----
` // #nosec G101

func TestToRSAPrivateKeyFromPem(t *testing.T) {
	decodedPrivateKey, _ := pem.Decode([]byte(privateKeyPEMExample))
	if decodedPrivateKey == nil {
		t.Fatal("failed to decode example PEM")
	}
	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(decodedPrivateKey.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		pemData []byte
		want    *rsa.PrivateKey
		err     error
	}{
		{
			name:    "success",
			pemData: []byte(privateKeyPEMExample),
			want:    rsaPrivateKey,
			err:     nil,
		},
		{
			name:    "fail PEM decode",
			pemData: []byte("invalid PEM data"),
			want:    nil,
			err:     errors.New("failed to decode PEM block"),
		},
		{
			name:    "fail not RSA private key",
			pemData: []byte("-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzF1I3k64K5X/Yz4Jt6DL\n-----END PUBLIC KEY-----"),
			want:    nil,
			err:     errors.New("not an RSA private key"),
		},
		{
			name:    "fail parse RSA private key",
			pemData: []byte("-----BEGIN RSA PRIVATE KEY-----\naW52YWxpZCBkYXRh\n-----END RSA PRIVATE KEY-----"),
			want:    nil,
			err:     asn1.StructuralError{Msg: "tags don't match (16 vs {class:1 tag:9 length:110 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} pkcs1PrivateKey @2"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			privateKey, caseErr := converter.ToRSAPrivateKeyFromPem(tt.pemData)

			assert.Equal(t, tt.want, privateKey)
			assert.Equal(t, tt.err, caseErr)
		})
	}
}
