package backup_test

import (
	"testing"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/extensions/backup"
	"github.com/karalef/quark/extensions/identity"
	"github.com/karalef/quark/extensions/subkey"
)

func TestBackup(t *testing.T) {
	key, sk, err := quark.Generate(sign.EDDilithium3, quark.NewValidity(0, 0))
	if err != nil {
		t.Fatal(err)
	}

	v := quark.NewValidity(0, 0)
	sub, ssk, err := subkey.GenerateSign(sign.EDDilithium3)
	if err = key.Sign(sk, sub.Certificate(), v); err != nil {
		t.Fatal(err)
	}

	ident := identity.New(identity.NewUserID("Name", "email", "comment"))
	if err = key.Sign(sk, ident.Certificate(), v); err != nil {
		t.Fatal(err)
	}

	bd := backup.BackupData{
		Key:     key,
		Certs:   []quark.Any{sub.Certificate(), ident.Certificate()},
		Secrets: []crypto.Key{sk, ssk},
	}
	scheme := encrypted.BuildPassphrase(aead.ChaCha20Poly1305, kdf.FromHash(hash.SHA256))
	source := encrypted.NewCounter(scheme.AEAD().NonceSize())

	b, err := backup.New(bd, "password", source, encrypted.PassphraseParams{
		Scheme:   scheme,
		Cost:     kdf.NewNoCost(),
		SaltSize: 32,
	})
	if err != nil {
		t.Fatal(err)
	}

	bd, err = b.Decrypt("password")
	if err != nil {
		t.Fatal(err)
	}
	if bd.Secrets[0].ID() != sk.ID() {
		t.Fatal("bad secret")
	}

	if bd.Secrets[1].ID() != ssk.ID() {
		t.Fatal("bad sub secret")
	}
}
