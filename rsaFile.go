package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

func getPublic(path string) (*rsa.PublicKey, error) {
	r, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(r)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey.(*rsa.PublicKey), nil
}

func getPrivate(path string) (*rsa.PrivateKey, error) {
	r, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(r)

	var cert interface{}
	if cert, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if cert, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil { // note this returns type `interface{}`
			return nil, errors.New("Chave privada não reconhecida")
		}
	}

	return cert.(*rsa.PrivateKey), nil
}
