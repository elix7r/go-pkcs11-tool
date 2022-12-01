package internal

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func Convert() {
	cert, err := os.ReadFile("")
	if err != nil {
		panic(err)
	}

	block, rest := pem.Decode(cert)
	if block == nil || block.Type != "PUBLIC KEY" {
		log.Fatal("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Got a %T, with remaining data: %q", pub, rest)
}
