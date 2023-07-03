package password

import (
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/ae"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
)

func TestPassword(t *testing.T) {
	noncryptoRand := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	testScheme := Build(
		ae.Build(ae.EncryptThanMAC, cipher.AESCTR128, mac.BLAKE2b128, xof.Shake128),
		kdf.Argon2i,
	)
	testPassword := "password"
	testData := []byte("testing data")
	testIV, _ := crypto.RandRead(noncryptoRand, testScheme.AE().Cipher().IVSize())
	testSalt, _ := crypto.RandRead(noncryptoRand, testScheme.AE().Cipher().KeySize())
	testKDFParams := kdf.Argon2Params{
		Rounds:  1,
		Memory:  8 * 1024,
		Threads: 1,
	}

	encryptedBuffer := make([]byte, len(testData))
	decryptedBuffer := make([]byte, len(testData))

	encrypter, err := testScheme.Encrypter(testPassword, testIV, testSalt, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	encrypter.Crypt(encryptedBuffer, testData)
	mac1 := encrypter.Tag(nil)

	decrypter, err := testScheme.Decrypter(testPassword, testIV, testSalt, testKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	decrypter.Crypt(decryptedBuffer, encryptedBuffer)
	mac2 := decrypter.Tag(nil)

	if !mac.Equal(mac1, mac2) {
		t.Fatal("MAC mismatch")
	}
}
