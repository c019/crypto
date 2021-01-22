package crypto

/*
In CBC mode, each block of plaintext is XORed with the previous ciphertext block before being encrypted.

	- In CBC Mode the given plaintext should be multiple of AES block size.
	- If the original plaintext lengths are not a multiple of the block size, padding would have to be added when encrypting
	- The IV value should be equal to AES block size.
	- CBC is block ciphers modes, encryption but not message integrity
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// Encrypt - ...
func (a *AesCBC) Encrypt() (string, error) {
	block, err := aes.NewCipher([]byte(a.Secret))
	if err != nil {
		return "", err
	}

	encrypt := make([]byte, aes.BlockSize+len(a.Texto))

	mode := cipher.NewCBCEncrypter(block, []byte(a.IV))

	mode.CryptBlocks(encrypt[aes.BlockSize:], []byte(a.Texto))

	return hex.EncodeToString(encrypt), nil
}

// Decrypt - ...
func (a *AesCBC) Decrypt() (string, error) {
	decrypt, err := hex.DecodeString(a.Texto)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(a.Secret))
	if err != nil {
		return "", err
	}

	decrypt = decrypt[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(decrypt)%aes.BlockSize != 0 {
		return "", errors.New("Não é um múltiplo do tamanho do bloco")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(a.IV))

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(decrypt, decrypt)

	return string(decrypt[:]), nil
}
