package gcm_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"

	"github.com/karalef/quark/crypto/aead/gcm"
)

var rnd = rand.New(rand.NewSource(123456789))

func Rand(n int) []byte {
	b := make([]byte, n)
	rnd.Read(b)
	return b
}

var (
	nonce     = Rand(gcm.NonceSize)
	ad        = Rand(12)
	plaintext = Rand(64)
	block, _  = aes.NewCipher(Rand(32))
)

func TestAES(t *testing.T) {
	std, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	stdFull := std.Seal(nil, nonce, plaintext, ad)
	ciphertext := stdFull[:len(stdFull)-16]
	tag := stdFull[len(stdFull)-16:]

	str := gcm.NewCipher(block, nonce, ad, 16)

	strCT := make([]byte, len(plaintext))
	str.Encrypt(strCT, plaintext)
	strTag := str.Tag(nil)

	if !bytes.Equal(ciphertext, strCT) {
		t.Fatal("ciphertext differ")
	}
	if !bytes.Equal(tag, strTag) {
		t.Fatal("tag differ after encryption")
	}

	strPT := make([]byte, len(plaintext))
	str = gcm.NewCipher(block, nonce, ad, 16)
	str.Decrypt(strPT, strCT[:20])
	str.Decrypt(strPT[20:], strCT[20:])
	strTag2 := str.Tag(nil)

	if !bytes.Equal(plaintext, strPT) {
		t.Fatal("plaintext differ")
	}
	if !bytes.Equal(strTag2, tag) {
		t.Fatal("tag differ after decryption")
	}
}

func TestReset(t *testing.T) {
	ciph := gcm.NewCipher(block, nonce, ad, 16)

	ciphertext := make([]byte, len(plaintext))
	ciph.Encrypt(ciphertext, plaintext)
	tag := ciph.Tag(nil)

	ciphertext2 := make([]byte, len(plaintext))
	ciph.Reset(nonce, ad)
	ciph.Encrypt(ciphertext2, plaintext)
	tag2 := ciph.Tag(nil)

	if !bytes.Equal(ciphertext, ciphertext2) {
		t.Fatal("ciphertext differ")
	}
	if !bytes.Equal(tag, tag2) {
		t.Fatal("tag differ after reset")
	}
}

func BenchmarkSTD(b *testing.B) {
	std, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 0, len(plaintext)+std.Overhead())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		std.Seal(buf, nonce, plaintext, ad)
	}
}

func BenchmarkGCM(b *testing.B) {
	g := gcm.NewCipher(block, nonce, ad, 16)
	buf := make([]byte, len(plaintext)+16)
	tag := buf[len(plaintext):len(plaintext)]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Encrypt(buf, plaintext)
		g.Tag(tag)
		g.Reset(nonce, ad)
	}
}

type pureAes struct{ b cipher.Block }

func (a pureAes) BlockSize() int          { return a.b.BlockSize() }
func (a pureAes) Encrypt(dst, src []byte) { a.b.Encrypt(dst, src) }
func (a pureAes) Decrypt(dst, src []byte) { a.b.Decrypt(dst, src) }

func BenchmarkSTDPure(b *testing.B) {
	std, err := cipher.NewGCM(pureAes{block})
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 0, len(plaintext)+std.Overhead())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		std.Seal(buf, nonce, plaintext, ad)
	}
}

func BenchmarkGCM_NoReset(b *testing.B) {
	buf := make([]byte, len(plaintext)+16)
	tag := buf[len(plaintext):]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g := gcm.NewCipher(block, nonce, ad, 16)
		g.Encrypt(buf, plaintext)
		g.Tag(tag)
	}
}
