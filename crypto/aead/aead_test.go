package aead

import (
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
)

func TestPassword(t *testing.T) {
	noncryptoRand := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	testScheme := Build(cipher.AESCTR256, mac.BLAKE2b128)
	testData := []byte("testing data")
	testSecret, _ := crypto.RandRead(noncryptoRand, 32)
	testIV, _ := crypto.RandRead(noncryptoRand, testScheme.Cipher().IVSize())
	testAD, _ := crypto.RandRead(noncryptoRand, 128)

	encryptedBuffer := make([]byte, len(testData))
	decryptedBuffer := make([]byte, len(testData))

	x := xof.Shake256.New()
	x.Write(testSecret)
	key := make([]byte, testScheme.Cipher().KeySize())
	macKey := make([]byte, testScheme.MAC().KeySize())
	x.Read(key)
	x.Read(macKey)

	encrypter, err := testScheme.Encrypter(testIV, key, macKey, testAD)
	if err != nil {
		t.Fatal(err)
	}
	encrypter.Crypt(encryptedBuffer, testData)
	mac1 := encrypter.Tag(nil)

	decrypter, err := testScheme.Decrypter(testIV, key, macKey, testAD)
	if err != nil {
		t.Fatal(err)
	}
	decrypter.Crypt(decryptedBuffer, encryptedBuffer)
	mac2 := decrypter.Tag(nil)

	if !mac.Equal(mac1, mac2) {
		t.Fatal("MAC mismatch")
	}

	if string(testData) != string(decryptedBuffer) {
		t.Fatal("decrypted data mismatch")
	}
}
