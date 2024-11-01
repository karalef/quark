package key_test

import (
	"testing"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/key"
	"github.com/karalef/quark/encrypted/password"
)

var testKeys = func() []sign.PrivateKey {
	r := make([]sign.PrivateKey, 5)
	for i := 0; i < len(r); i++ {
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

func TestEncrypter(t *testing.T) {
	subs := make([]key.Sub, len(testKeys))
	pass := passParams.New()
	enc, err := key.NewEncrypter("password", nil, pass)
	if err != nil {
		t.Fatal(err)
	}
	for i := range testKeys {
		subs[i], err = enc.Encrypt(testKeys[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	crypter, err := pass.NewCrypter("password")
	if err != nil {
		t.Fatal(err)
	}
	for i := range subs {
		k, err := subs[i].DecryptSign(crypter)
		if err != nil {
			t.Fatal(err)
		}
		if !k.Equal(testKeys[i]) {
			t.Fatal("mismatch")
		}
	}
}
