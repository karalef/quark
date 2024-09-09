package backup_test

import (
	"testing"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/extensions/backup"
	"github.com/karalef/quark/extensions/subkey"
)

func TestBackup(t *testing.T) {
	ident, sk, err := quark.Generate(sign.EDDilithium3, 0)
	if err != nil {
		t.Fatal(err)
	}

	ssk, spk, err := sign.Generate(sign.EDDilithium3, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subkey.BindSign(ident, sk, spk, 0)
	if err != nil {
		t.Fatal(err)
	}

	ksk, kpk, err := kem.Generate(kem.Kyber768, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subkey.BindKEM(ident, sk, kpk, 0)
	if err != nil {
		t.Fatal(err)
	}

	b, err := backup.New(backup.BackupData{
		Identity: ident,
		Secret:   sk,
		Subkeys:  []crypto.Key{ssk, ksk},
	}, "password", encrypted.PassphraseParams{
		Scheme: password.Build(aead.Build(cipher.AESCTR256, mac.BLAKE3), kdf.Argon2i),
		Cost: kdf.Cost{
			CPU:         1,
			Memory:      1 * 1024,
			Parallelism: 1,
		},
		SaltSize: 32,
	})
	if err != nil {
		t.Fatal(err)
	}

	bd, err := b.Decrypt("password")
	if err != nil {
		t.Fatal(err)
	}

	if bd.Identity.ID() != ident.ID() {
		t.Fatal("bad identity")
	}
}
