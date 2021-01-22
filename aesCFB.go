package crypto

/*
The Cipher Feedback (CFB) mode, a close relative of CBC, makes a block cipher into a
self-synchronizing stream cipher. Operation is very similar; in particular, CFB decryption is almost
identical to CBC encryption performed in reverse:

	- CFB's pseudo random stream depends on the plaintext
	- A different nonce or random IV is needed for every message.
	- CFB is block ciphers modes, encryption but not message integrity
*/

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
)

// Encrypt - ...
func (a *AesCFB) Encrypt() (string, error) {
	block, err := aes.NewCipher([]byte(a.Secret))
	if err != nil {
		return "", err
	}

	encrypt := make([]byte, aes.BlockSize+len(a.Texto))

	mode := cipher.NewCFBEncrypter(block, []byte(a.IV))

	mode.XORKeyStream(encrypt[aes.BlockSize:], []byte(a.Texto))

	return hex.EncodeToString(encrypt), nil
}

// Decrypt - ...
func (a *AesCFB) Decrypt() (string, error) {
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

	mode := cipher.NewCFBDecrypter(block, []byte(a.IV))

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.XORKeyStream(decrypt, decrypt)

	return string(decrypt[:]), nil
}
