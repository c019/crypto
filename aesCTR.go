package crypto

/*
CTR mode has similar characteristics to OFB, but also allows a random access property during
decryption. CTR mode is well suited to operate on a multi-processor machine where blocks can be
encrypted in parallel. Furthermore, it does not suffer from the short-cycle problem that can affect
OFB.

	- In CTR Mode the given plaintext should be multiple of AES block size.
	- If the original plaintext lengths are not a multiple of the block size, padding would have to be added when encrypting
	- The IV value should be equal to AES block size.
	- CTR is block ciphers modes, encryption but not message integrity
	- Because of the symmetry of the XOR operation, encryption and decryption are exactly the same
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// Encrypt - ...
func (a *AesCTR) Encrypt() (string, error) {
	block, err := aes.NewCipher([]byte(a.Secret))
	if err != nil {
		return "", err
	}

	encrypt := make([]byte, aes.BlockSize+len(a.Texto))

	mode := cipher.NewCTR(block, []byte(a.IV))

	mode.XORKeyStream(encrypt[aes.BlockSize:], []byte(a.Texto))

	return hex.EncodeToString(encrypt), nil
}

// Decrypt - ...
func (a *AesCTR) Decrypt() (string, error) {
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

	mode := cipher.NewCTR(block, []byte(a.IV))
	mode.XORKeyStream(decrypt, decrypt)

	return string(decrypt[:]), nil
}
