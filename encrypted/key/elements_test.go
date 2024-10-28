package key_test

import (
	"testing"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/key"
	"github.com/karalef/quark/encrypted/password"
)

var testKeys = func() []sign.PrivateKey {
	r := make([]sign.PrivateKey, 2)
	for i := 0; i < 2; i++ {
		sk, _, err := sign.Generate(sign.EDDilithium3, nil)
		if err != nil {
			panic(err)
		}
		r[i] = sk
	}
	return r
}()

var passParams = encrypted.PassphraseParams{
	Scheme:   password.Build(aead.ChaCha20Poly1305, kdf.Argon2i),
	Cost:     &kdf.Argon2Cost{Time: 1, Memory: 1024, Threads: 1},
	SaltSize: 16,
}

func TestElement(t *testing.T) {
	pp := encrypted.NewPassphrase(passParams)
	crypter := crypto.OrPanic(pp.NewCrypter("password"))
	el, err := key.EncryptElement(testKeys[0], crypter, crypto.Rand(passParams.Scheme.AEAD().NonceSize()))
	if err != nil {
		t.Fatal(err)
	}
	el2, err := key.EncryptElement(testKeys[1], crypter, crypto.Rand(passParams.Scheme.AEAD().NonceSize()))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := el.Decrypt(crypter)
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := el2.Decrypt(crypter)
	if err != nil {
		t.Fatal(err)
	}
	if !sk.(sign.PrivateKey).Equal(testKeys[0]) {
		t.Fatal("mismatch 1")
	}
	if !sk2.(sign.PrivateKey).Equal(testKeys[1]) {
		t.Fatal("mismatch 2")
	}
}

func TestEncrypter(t *testing.T) {
	enc, pp, err := key.NewEncrypter("password", nil, passParams)
	if err != nil {
		t.Fatal(err)
	}
	e := make([]key.Element, 2)
	for i, sk := range testKeys {
		el, err := enc.Encrypt(sk)
		if err != nil {
			t.Fatal(err)
		}
		e[i] = el
	}

	crypter, err := pp.NewCrypter("password")
	if err != nil {
		t.Fatal(err)
	}
	d := make([]sign.PrivateKey, 2)
	for i, el := range e {
		sk, err := el.Decrypt(crypter)
		if err != nil {
			t.Fatal(err)
		}
		d[i] = sk.(sign.PrivateKey)
	}

	for i, sk := range d {
		if !sk.Equal(testKeys[i]) {
			t.Fatal("mismatch", i)
		}
	}
}
