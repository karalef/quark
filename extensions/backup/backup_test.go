package backup_test

import (
	"testing"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/password"
	"github.com/karalef/quark/extensions/backup"
	"github.com/karalef/quark/extensions/subkey"
)

func TestBackup(t *testing.T) {
	ident, sk, err := quark.Generate(sign.EDDilithium3)
	if err != nil {
		t.Fatal(err)
	}

	ssk, spk, err := sign.Generate(sign.EDDilithium3, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subkey.BindSign(ident, sk, 0, spk, subkey.UsageSign)
	if err != nil {
		t.Fatal(err)
	}

	ksk, kpk, err := kem.Generate(kem.Kyber768, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subkey.BindKEM(ident, sk, 0, kpk, subkey.UsageEncrypt)
	if err != nil {
		t.Fatal(err)
	}

	bd := backup.BackupData{
		Key:     ident,
		Secret:  sk,
		Subkeys: []crypto.Key{ssk, ksk},
	}
	scheme := password.Build(aead.ChaCha20Poly1305, kdf.Argon2i)
	cost := &kdf.Argon2Cost{Time: 1, Memory: 1 * 1024, Threads: 1}
	source := encrypted.NewCounter(uint8(scheme.AEAD().NonceSize()))

	b, err := backup.New(bd, "password", source, encrypted.PassphraseParams{
		Scheme:   scheme,
		Cost:     cost,
		SaltSize: 32,
	})
	if err != nil {
		t.Fatal(err)
	}

	bd, err = b.Decrypt("password")
	if err != nil {
		t.Fatal(err)
	}

	if bd.Key.ID() != ident.ID() {
		t.Fatal("bad identity")
	}
}
