package pkg

import (
	"crypto/rand"
	"fmt"
	"io"
)

func RandomKeyID() (string, error) {
	random_key := make([]byte, 2)
	n, err := io.ReadFull(rand.Reader, random_key)
	if n != len(random_key) || err != nil {
		return "", err
	}
	return fmt.Sprintf("%0x%0x", random_key[0], random_key[1]), nil
}
