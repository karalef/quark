package ssead_test

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/crypto/sign/eddilithium"
	"github.com/karalef/quark/exp/ssead"
)

var rnd = rand.New(rand.NewSource(0))

func Rand(n int) []byte {
	b := make([]byte, n)
	rnd.Read(b)
	return b
}

var (
	signat = eddilithium.ED448Mode3
	scheme = ssead.New("TEST", cipher.AESCTR, signat)
	pk, sk = crypto.Generate(signat)
	pt     = []byte("plaintext")
	ct     = make([]byte, len(pt))
	sig    []byte
)

func TestSSEAD(t *testing.T) {
	key := Rand(scheme.KeySize())
	iv := Rand(scheme.IVSize())
	ad := []byte("associated data")

	enc := scheme.Encrypt(sk.(sign.PrivateKey), key, iv, ad)
	enc.Encrypt(ct, pt)
	sig = enc.Sign()

	// normal
	err := decrypt(ct, key, iv, ad)
	if err != nil {
		t.Fatal(err)
	}

	// tampered iv
	err = decrypt(ct, key, Rand(len(iv)), ad)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Log(err)

	// tampered ad
	err = decrypt(ct, key, iv, Rand(len(ad)))
	if err == nil {
		t.Fatal("expected error")
	}
	t.Log(err)

	// tampered key
	err = decrypt(ct, Rand(len(key)), iv, ad)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Log(err)

	// tampered ct
	tct := bytes.Clone(ct)
	tct[0] ^= 123
	err = decrypt(Rand(len(ct)), key, iv, ad)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Log(err)

	// tampered signature
	sig[0] ^= 123
	err = decrypt(ct, key, iv, ad)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Log(err)

	// invalid signature
	sig = sig[1:]
	err = decrypt(ct, key, iv, ad)
	if err == nil {
		t.Fatal("expected error")
	}
	t.Log(err)
}

func decrypt(ct, key, iv, ad []byte) error {
	dec := scheme.Decrypt(pk.(sign.PublicKey), key, iv, ad)
	decrypted := make([]byte, len(pt))
	dec.Decrypt(decrypted, ct)
	ok, err := dec.Verify(sig)
	if err != nil {
		return errVerify
	}
	if !ok {
		return errSig
	}
	if string(decrypted) != string(pt) {
		return errPT
	}
	return nil
}

var (
	errVerify = errors.New("verification error")
	errSig    = errors.New("wrong signature")
	errPT     = errors.New("wrong plaintext")
)
