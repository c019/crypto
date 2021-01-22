package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Encrypt - Encriptar
func (r *RsaOAEP) Encrypt() (string, error) {
	rng := rand.Reader

	if r.PathPublicKey == "" {
		return "", errors.New("Chave PathPublicKey não definida")
	}

	rsaPublic, err := getPublic(r.PathPublicKey)
	if err != nil {
		return "", err
	}

	encrypt, err := rsa.EncryptOAEP(sha256.New(), rng, rsaPublic, []byte(r.Texto), r.Label)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", encrypt[:]), nil
}

// Decrypt - Encriptar
func (r *RsaOAEP) Decrypt() (string, error) {
	rng := rand.Reader

	if r.PathPrivateKey == "" {
		return "", errors.New("Chave PathPrivateKey não definida")
	}

	rsaPrivate, err := getPrivate(r.PathPrivateKey)
	if err != nil {
		return "", err
	}

	textoHex, err := hex.DecodeString(r.Texto)
	if err != nil {
		return "", err
	}

	decrypt, err := rsa.DecryptOAEP(sha256.New(), rng, rsaPrivate, textoHex, r.Label)
	if err != nil {
		return "", err
	}

	return string(decrypt[:]), nil
}
