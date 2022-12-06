package pkg

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

func LoadCert(filePath string) (*x509.Certificate, error) {
	r, _ := os.ReadFile(filePath)
	block, _ := pem.Decode(r)
	// fmt.Println(block.Type)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
