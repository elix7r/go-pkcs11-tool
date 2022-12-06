package pkg

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func LoadPubKey(filePath string) *rsa.PublicKey {
	file, err := os.ReadFile(filePath)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(file)
	pkey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	rsaKey, ok := pkey.(*rsa.PublicKey)
	if !ok {
		log.Fatalf("got unexpected key type: %T", pkey)
	}
	return rsaKey
}
