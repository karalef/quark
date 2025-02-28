# Quark

Quark is a post-quantum crypto-secure crypto library.

## Why?

*"Imagine that it's fifteen years from now. Somebody announces that he's built a large quantum computer. RSA is dead. DSA is dead. Elliptic curves, hyperelliptic curves, class groups, whatever, dead, dead, dead. So users are going to run around screaming and say 'Oh my God, what do we do?'..."* - https://pqcrypto.org

# Warning

Be careful when using cryptographic libraries implemented by non-cryptographers (including this one), as they may contain vulnerabilities.

## Usage

#### [Using go](https://pkg.go.dev/cmd/go#hdr-Compile_and_install_packages_and_dependencies)
```sh
go get github.com/karalef/quark
```

### Sign/Verify
```go
package main

import (
    "time"

    "github.com/karalef/quark/crypto"
    "github.com/karalef/quark/crypto/sign"
)

func main() {
    // Generate a new ML-DSA-65 key pair.
    pk, sk := crypto.Generate(sign.MLDSA65)

    msg := []byte("Hello, world!")

    signer := sk.Sign()
    signer.Write(msg)
    signature := signer.Sign()

    verifier := pk.Verify()
    verifier.Write(msg)
    ok, err := verifier.Verify(signature)
    if err != nil {
        panic("Signature is invalid (not correspond to the algorithm)")
    }
    if !ok {
        panic("Signature is wrong")
    }
}
```

### Encrypt/Decrypt
```go
package main

import (
	"bytes"
	"strconv"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
)

// generate KEM key pair
var pk, sk = crypto.Generate(kem.MLKEM768)

func main() {
	s, data := Send("Hello")
	Receive(s, data, "Hello")
}

func Send(msg string) (quark.Sealed, [][]quark.Data) {
	cipher := aead.ChaCha20Poly1305 // cipher scheme
	kdfSch := kdf.HMAC_SHA3         // KDF scheme

	// encapsulate a random shared secret and derive a master key.
	sealed, master, err := quark.Seal(pk, cipher, kdfSch, 16)
	if err != nil {
		panic(err)
	}

	data := make([][]quark.Data, 10)
	for i := range 10 {
		// create a nonce source to encrypt several parts with the same key.
		ns := quark.NewLFSR(master.Scheme.NonceSize(), 0)

		// info is a some data to expand the master key and derive a cipher key.
		info := []byte("testing " + strconv.Itoa(i))

		// expand the master key using info and create an encrypter
		enc, err := master.Encrypter(info, ns)
		if err != nil {
			panic(err)
		}

		data[i] = make([]quark.Data, 10)
		for j := range 10 {
			plaintext := []byte(msg + strconv.Itoa(i) + strconv.Itoa(j))
			ad := []byte{byte(i), byte(j)}

			// encrypt data with optional additional data
			ed, err := enc.EncryptData(plaintext, ad)
			if err != nil {
				panic(err)
			}
			data[i][j] = ed
		}
	}

	return sealed, data
}

func Receive(s quark.Sealed, data [][]quark.Data, must string) {
	// extract the master key from encapsulated shared secret.
	master, err := s.Extract(sk)
	if err != nil {
		panic(err)
	}

	for i := range len(data) {
		// info is a some data to expand the master key and derive a cipher key.
		info := []byte("testing " + strconv.Itoa(i))

		// expand the master key using info and create a cipher.
		ciph, err := master.New(info)
		if err != nil {
			panic(err)
		}

		for j := range 10 {
			mustBe := []byte(must + strconv.Itoa(i) + strconv.Itoa(j))
			ad := []byte{byte(i), byte(j)}

			// decrypt data with optional additional data.
			// DecryptDataBuf uses internal buffer to not modify the data.
			pt, err := ciph.DecryptDataBuf(data[i][j], ad)
			if err != nil {
				panic(err)
			}

			if !bytes.Equal(pt, mustBe) {
				panic("decrypted data does not match")
			}
		}
	}
}
```
