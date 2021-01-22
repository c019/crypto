# Crypto

Diversos modos de criptografia para GoLang

## Installation

To install try package, you need to install Go and set your Go workspace first.

1. Download and install it:

```sh
$ go get -u github.com/c019/crypto
```

2. Import it in your code:

```go
import "github.com/c019/crypto"
```

## API examples:

```go
package main

import (
	"github.com/c019/crypto"
)

func main() {
  sha256 := crypto.Sha256{
		Texto: "NADA",
	}

	fmt.Println(sha256.Encrypt())
}
```

> OBS: Caso queria gerar os arquivos SSL para utilização da criptografia RSA
```shell
openssl req -new -x509 -sha256 -newkey rsa:2048 -nodes -keyout modelo.key.pem -out modelo.cert.pem -subj "/C=BR/ST=PR/O=Modelo"
```