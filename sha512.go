package crypto

import (
	"crypto/sha512"
	"fmt"
)

// Encrypt - Funcao para criptografar utilizando o SHA512
func (s *Sha512) Encrypt() string {
	h := sha512.New()
	h.Write([]byte(s.Texto))

	if s.Hash != "" {
		return fmt.Sprintf("%x", h.Sum([]byte(s.Hash)))
	}

	return fmt.Sprintf("%x", h.Sum(nil)[:])
}
