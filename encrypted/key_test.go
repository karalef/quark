package encrypted_test

import (
	"testing"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
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
	Scheme:   encrypted.BuildPassphrase(aead.ChaCha20Poly1305, kdf.FromHash(hash.SHA256)),
	Cost:     kdf.NewNoCost(),
	SaltSize: 16,
}

func TestEncrypter(t *testing.T) {
	subs := make([]encrypted.Key[sign.PrivateKey], len(testKeys))
	pass := passParams.New()
	enc, err := encrypted.NewKeyEncrypter[sign.PrivateKey]("password", nil, pass)
	if err != nil {
		t.Fatal(err)
	}
	for i := range testKeys {
		subs[i], err = enc.Encrypt(testKeys[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	crypter, err := pass.Crypter("password")
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
