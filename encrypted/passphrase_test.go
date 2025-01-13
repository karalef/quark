package encrypted

import (
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
)

func TestPassphrase(t *testing.T) {
	noncryptoRand := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	testScheme := BuildPassphrase(aead.ChaCha20Poly1305, kdf.FromHash(hash.SHA256))
	testPassphrase := "passphrase"
	testData := []byte("testing data")
	testIV, _ := crypto.RandRead(noncryptoRand, testScheme.NonceSize())
	testSalt, _ := crypto.RandRead(noncryptoRand, 16)
	testAD, _ := crypto.RandRead(noncryptoRand, 128)

	encryptedBuffer := make([]byte, len(testData))
	decryptedBuffer := make([]byte, len(testData))

	encrypter, err := testScheme.Encrypter(testPassphrase, testIV, testSalt, testAD, kdf.NewNoCost())
	if err != nil {
		t.Fatal(err)
	}
	encrypter.Crypt(encryptedBuffer, testData)
	mac1 := encrypter.Tag(nil)

	decrypter, err := testScheme.Decrypter(testPassphrase, testIV, testSalt, testAD, kdf.NewNoCost())
	if err != nil {
		t.Fatal(err)
	}
	decrypter.Crypt(decryptedBuffer, encryptedBuffer)
	mac2 := decrypter.Tag(nil)

	if !mac.Equal(mac1, mac2) {
		t.Fatal("MAC mismatch")
	}
}
