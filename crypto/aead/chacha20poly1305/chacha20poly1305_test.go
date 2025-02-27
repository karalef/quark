package chacha20poly1305_test

import (
	"bytes"
	"math/rand"
	"testing"

	stream "github.com/karalef/quark/crypto/aead/chacha20poly1305"
	std "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

var rnd = rand.New(rand.NewSource(123456789))

func Rand(n int) []byte {
	b := make([]byte, n)
	rnd.Read(b)
	return b
}

var (
	testKey    = Rand(stream.KeySize)
	testNonce  = Rand(stream.NonceSize)
	testNonceX = Rand(stream.NonceSizeX)
	testData   = []byte("test data")
	testAD     = Rand(128)
)

func TestChaCha20(t *testing.T) {
	stdCiph, err := std.New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed := stdCiph.Seal(nil, testNonce, testData, testAD)
	ciphertext := sealed[:len(testData)]
	tag := sealed[len(testData):]

	strBuf := make([]byte, len(testData))
	strCiph := stream.New(testKey, testNonce, testAD)
	strCiph.Encrypt(strBuf, testData)

	if !bytes.Equal(strBuf, ciphertext) {
		t.Fatal("mismatch ciphertext")
	}
	if !bytes.Equal(strCiph.Tag(nil), tag) {
		t.Fatal("mismatch tag (encryption)")
	}

	strCiph = stream.New(testKey, testNonce, testAD)
	strCiph.Decrypt(strBuf, strBuf)

	if !bytes.Equal(strBuf, testData) {
		t.Fatal("mismatch plaintext")
	}
	if !bytes.Equal(strCiph.Tag(nil), tag) {
		t.Fatal("mismatch tag (decryption)")
	}
}

func TestXChaCha20(t *testing.T) {
	stdCiph, err := std.NewX(testKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed := stdCiph.Seal(nil, testNonceX, testData, testAD)
	ciphertext := sealed[:len(testData)]
	tag := sealed[len(testData):]

	strBuf := make([]byte, len(testData))
	strCiph := stream.New(testKey, testNonceX, testAD)
	strCiph.Encrypt(strBuf, testData)

	if !bytes.Equal(strBuf, ciphertext) {
		t.Fatal("mismatch ciphertext")
	}
	if !bytes.Equal(strCiph.Tag(nil), tag) {
		t.Fatal("mismatch tag (encryption)")
	}

	strCiph = stream.New(testKey, testNonceX, testAD)
	strCiph.Decrypt(strBuf, strBuf)

	if !bytes.Equal(strBuf, testData) {
		t.Fatal("mismatch plaintext")
	}
	if !bytes.Equal(strCiph.Tag(nil), tag) {
		t.Fatal("mismatch tag (decryption)")
	}
}

func BenchmarkChaCha20Poly1305(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ciph := stream.New(testKey, testNonce, testAD)
		ciph.Encrypt(testData, testData)
	}
}

func BenchmarkStdChaCha20Poly1305_NoSSSE3(b *testing.B) {
	cpu.X86.HasSSSE3 = false
	for i := 0; i < b.N; i++ {
		ciph, _ := std.New(testKey)
		ciph.Seal(testData[:0], testNonce, testData, testAD)
	}
	cpu.X86.HasSSSE3 = true
}

func BenchmarkStdChaCha20Poly1305(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ciph, _ := std.New(testKey)
		ciph.Seal(testData[:0], testNonce, testData, testAD)
	}
}
