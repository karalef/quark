package kem

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/karalef/quark/cipher"
)

var testmsg = "Message that exists just for testing purposess"

func Test_KEM_xChaCha20Poly1305(t *testing.T) {
	t.Logf("Test message: %s", testmsg)

	s := Kyber768.Scheme()
	if s == nil {
		t.Fatal(ErrInvalidKeyAlgorithm)
	}
	priv, pub, err := s.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cipheredKey, key, err := pub.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Generated shared secret: %s", base64.RawStdEncoding.EncodeToString(key))

	ciph, err := genCipher(cipher.XChacha20Poly1305, key)
	if err != nil {
		t.Fatal(err)
	}

	nonce := make([]byte, ciph.Scheme().NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		t.Fatal(err)
	}

	ciphertext := ciph.Seal(nil, nonce, []byte(testmsg))

	plainkey, err := priv.Decapsulate(cipheredKey)
	if err != nil || string(plainkey) != string(key) {
		t.Fatal(err)
	}

	t.Logf("Decapsulated shared secret: %s", base64.RawStdEncoding.EncodeToString(plainkey))

	ciph, err = genCipher(cipher.XChacha20Poly1305, plainkey)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := ciph.Open(nil, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if string(plaintext) != testmsg {
		t.Fatal("plaintext does not match")
	}

	t.Logf("plaintext: %s", string(plaintext))
}

func genCipher(alg cipher.Algorithm, key []byte) (cipher.Cipher, error) {
	sch := alg.Scheme()
	if sch == nil {
		return nil, cipher.ErrInvalidKeyAlgorithm
	}
	return sch.Unpack(key)
}
