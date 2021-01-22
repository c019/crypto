package crypto

// Sha256 - ...
type Sha256 struct {
	Texto string
	Hash  string
}

// Sha512 - ...
type Sha512 struct {
	Texto string
	Hash  string
}

// RsaOAEP - ...
type RsaOAEP struct {
	Texto          string
	Label          []byte
	PathPrivateKey string
	PathPublicKey  string
}

// aesBase - Estrutura Base para as criptografia AES
type aesBase struct {
	Texto          string
	Secret         string
	IV             string
	AdditionalData string
}

// AesGCM - ...
type AesGCM aesBase

// AesCBC - ...
type AesCBC aesBase

// AesCFB - ...
type AesCFB aesBase

// AesCTR - ...
type AesCTR aesBase

// AesOFB - ...
type AesOFB aesBase
