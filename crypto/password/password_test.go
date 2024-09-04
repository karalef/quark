package password

import (
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
)

func TestPassword(t *testing.T) {
	noncryptoRand := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	testScheme := Build(
		aead.Build(cipher.AESCTR256, mac.BLAKE2b128),
		kdf.Argon2i,
	)
	testPassword := "password"
	testData := []byte("testing data")
	testIV, _ := crypto.RandRead(noncryptoRand, testScheme.AEAD().Cipher().IVSize())
	testSalt, _ := crypto.RandRead(noncryptoRand, testScheme.AEAD().Cipher().KeySize())
	testAD, _ := crypto.RandRead(noncryptoRand, 128)
	testKDFParams := kdf.Cost{
		CPU:         1,
		Memory:      8 * 1024,
		Parallelism: 1,
	}

	encryptedBuffer := make([]byte, len(testData))
	decryptedBuffer := make([]byte, len(testData))

	encrypter, err := testScheme.Encrypter(testPassword, testIV, testSalt, testAD, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	encrypter.Crypt(encryptedBuffer, testData)
	mac1 := encrypter.Tag(nil)

	decrypter, err := testScheme.Decrypter(testPassword, testIV, testSalt, testAD, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	decrypter.Crypt(decryptedBuffer, encryptedBuffer)
	mac2 := decrypter.Tag(nil)

	if !mac.Equal(mac1, mac2) {
		t.Fatal("MAC mismatch")
	}
}
