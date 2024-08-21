package quark

import (
	"os"
	"testing"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

func TestPrivate(t *testing.T) {
	_, sk, err := Generate(sign.EDDilithium3, 0)
	if err != nil {
		t.Fatal(err)
	}

	enc, err := EncryptKey(sk, "pass", password.Build(aead.Build(cipher.AESCTR256, mac.BLAKE2b128), kdf.Argon2i), &kdf.Argon2Params{
		Rounds:  2,
		Memory:  8 * 1024,
		Threads: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	wc, err := pack.ArmoredEncoder(os.Stderr, enc.PacketTag().BlockType(), nil)
	if err != nil {
		t.Fatal(err)
	}

	err = pack.Pack(wc, enc)
	if err != nil {
		t.Fatal(err)
	}
	wc.Close()

	sk2, err := enc.Decrypt("pass")
	if err != nil {
		t.Fatal(err)
	}
	if !sk.Raw().Equal(sk2.Raw()) {
		t.Fatal("sk != sk2")
	}
}
