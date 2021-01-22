package crypto

/*
GCM is a block cipher counter mode with authentication. A Counter mode effectively turns a block
cipher into a stream cipher, and therefore many of the rules for stream ciphers still apply.

	- GCM mode provides both privacy (encryption) and integrity.
	- GCM uses an IV (or Nonce)
	- Same(Key) + Same (IV) will always produce same PRNG stream, so for best security practices always re-generate the IV while performing encryption and use the same IV for decryption.
	- GCM is authenticated encryption (both encryption and message integrity)
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
)

// Encrypt - ...
func (a *AesGCM) Encrypt() (string, error) {
	block, err := aes.NewCipher([]byte(a.Secret))
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	var encrypt []byte
	if a.AdditionalData != "" {
		encrypt = aesgcm.Seal(nil, []byte(a.IV), []byte(a.Texto), []byte(a.AdditionalData))
	} else {
		encrypt = aesgcm.Seal(nil, []byte(a.IV), []byte(a.Texto), nil)
	}

	return hex.EncodeToString(encrypt), nil
}

// Decrypt - ...
func (a *AesGCM) Decrypt() (string, error) {
	ciphertext, _ := hex.DecodeString(a.Texto)

	block, err := aes.NewCipher([]byte(a.Secret))
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	decrypt, err := aesgcm.Open(nil, []byte(a.IV), ciphertext, []byte(a.AdditionalData))
	if err != nil {
		return "", err
	}

	return string(decrypt[:]), nil
}
