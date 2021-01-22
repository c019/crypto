package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"io"
)

// GenerateAesIV - Gerar um IV para o AES
func GenerateAesIV() (string, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	return string(iv), nil
}
