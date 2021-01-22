package crypto

/*
The Output Feedback (OFB) mode makes a block cipher into a synchronous stream cipher. It generates
keystream blocks, which are then XORed with the plaintextblocks to get the ciphertext. Just as with
other stream ciphers, flipping a bit in the ciphertext produces a flipped bit in the plaintext at
the same location.

	- In OFB Mode the given plaintext should be multiple of AES block size.
	- If the original plaintext lengths are not a multiple of the block size, padding would have to be added when encrypting
	- The IV value should be equal to AES block size.
	- OFB is block ciphers modes, encryption but not message integrity
	- Because of the symmetry of the XOR operation, encryption and decryption are exactly the same
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// Encrypt - ...
func (a *AesOFB) Encrypt() (string, error) {
	block, err := aes.NewCipher([]byte(a.Secret))
	if err != nil {
		return "", err
	}

	encrypt := make([]byte, aes.BlockSize+len(a.Texto))

	mode := cipher.NewOFB(block, []byte(a.IV))

	mode.XORKeyStream(encrypt[aes.BlockSize:], []byte(a.Texto))

	return hex.EncodeToString(encrypt), nil
}

// Decrypt - ...
func (a *AesOFB) Decrypt() (string, error) {
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

	mode := cipher.NewOFB(block, []byte(a.IV))

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.XORKeyStream(decrypt, decrypt)

	return string(decrypt[:]), nil
}
