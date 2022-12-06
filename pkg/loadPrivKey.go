package pkg

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func LoadPrivKey(filePath string) *rsa.PrivateKey {
	file, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(file)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}
