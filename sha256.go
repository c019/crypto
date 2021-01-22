package crypto

import (
	"crypto/sha256"
	"fmt"
)

// Encrypt - Funcao para criptografar utilizando o SHA256
func (s *Sha256) Encrypt() string {
	h := sha256.New()
	h.Write([]byte(s.Texto))

	if s.Hash != "" {
		return fmt.Sprintf("%x", h.Sum([]byte(s.Hash)))
	}

	return fmt.Sprintf("%x", h.Sum(nil)[:])
}
