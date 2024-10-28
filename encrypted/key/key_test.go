package key_test

import (
	"testing"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted/key"
	"github.com/karalef/quark/encrypted/password"
)

func TestKey(t *testing.T) {
	sk, _, err := sign.Generate(sign.EDDilithium3, nil)
	if err != nil {
		t.Fatal(err)
	}
	scheme := password.Build(aead.ChaCha20Poly1305, kdf.Argon2i)
	k, err := key.Encrypt(sk, "password", crypto.Rand(scheme.AEAD().NonceSize()), passParams)
	if err != nil {
		t.Fatal(err)
	}
	sk2, err := k.DecryptSign("password")
	if err != nil {
		t.Fatal(err)
	}

	if !sk.Equal(sk2) {
		t.Fatal("mismatch")
	}
}
