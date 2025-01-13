package encrypted

import (
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
)

func TestSecret(t *testing.T) {
	noncryptoRand := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	testScheme := BuildSecret(aead.ChaCha20Poly1305, xof.BLAKE3x)
	testSecret, _ := crypto.RandRead(noncryptoRand, 32)
	testIV, _ := crypto.RandRead(noncryptoRand, testScheme.NonceSize())
	testData := []byte("testing data")
	testAD, _ := crypto.RandRead(noncryptoRand, 128)

	encryptedBuffer := make([]byte, len(testData))
	decryptedBuffer := make([]byte, len(testData))

	encrypter, err := testScheme.Encrypter(testIV, testSecret, testAD)
	if err != nil {
		t.Fatal(err)
	}
	encrypter.Crypt(encryptedBuffer, testData)
	mac1 := encrypter.Tag(nil)

	decrypter, err := testScheme.Decrypter(testIV, testSecret, testAD)
	if err != nil {
		t.Fatal(err)
	}
	decrypter.Crypt(decryptedBuffer, encryptedBuffer)
	mac2 := decrypter.Tag(nil)

	if !mac.Equal(mac1, mac2) {
		t.Fatal("MAC mismatch")
	}
}
