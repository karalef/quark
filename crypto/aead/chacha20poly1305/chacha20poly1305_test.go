package chacha20poly1305_test

import (
	"bytes"
	"testing"

	"github.com/karalef/quark/crypto"
	stream "github.com/karalef/quark/crypto/aead/chacha20poly1305"
	"github.com/karalef/quark/crypto/mac"
	std "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

var (
	testKey    = crypto.Rand(stream.KeySize)
	testNonce  = crypto.Rand(stream.NonceSize)
	testNonceX = crypto.Rand(stream.NonceSizeX)
	testData   = []byte("test data")
	testAD     = crypto.Rand(128)
)

func TestChaCha20(t *testing.T) {
	buf1 := make([]byte, len(testData))
	enc := stream.NewEncrypter(testKey, testNonce, testAD)
	enc.Crypt(buf1, testData)
	tag1 := enc.Tag(nil)

	ciph2, err := std.New(testKey)
	if err != nil {
		t.Fatal(err)
	}
	buf2 := ciph2.Seal(nil, testNonce, testData, testAD)
	if !bytes.Equal(append(buf1, tag1...), buf2) {
		t.Fatal("mismatch")
	}

	dec := stream.NewDecrypter(testKey, testNonce, testAD)
	dec.Crypt(buf1, buf1)
	tag := dec.Tag(nil)

	buf2, err = ciph2.Open(buf2[:0], testNonce, buf2, testAD)
	if err != nil {
		t.Fatal(err)
	}
	if !mac.Equal(tag1, tag) {
		t.Fatal("mismatch")
	}
}

func TestXChaCha20(t *testing.T) {
	buf1 := make([]byte, len(testData))
	enc := stream.NewEncrypter(testKey, testNonceX, testAD)
	enc.Crypt(buf1, testData)
	tag1 := enc.Tag(nil)

	ciph2, err := std.NewX(testKey)
	if err != nil {
		t.Fatal(err)
	}
	buf2 := ciph2.Seal(nil, testNonceX, testData, testAD)
	if !bytes.Equal(append(buf1, tag1...), buf2) {
		t.Fatal("mismatch")
	}

	dec := stream.NewDecrypter(testKey, testNonceX, testAD)
	dec.Crypt(buf1, buf1)
	tag := dec.Tag(nil)

	buf2, err = ciph2.Open(buf2[:0], testNonceX, buf2, testAD)
	if err != nil {
		t.Fatal(err)
	}
	if !mac.Equal(tag1, tag) {
		t.Fatal("mismatch")
	}
}

func BenchmarkChaCha20Poly1305(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ciph := stream.NewEncrypter(testKey, testNonce, testAD)
		ciph.Crypt(testData, testData)
	}
}

func BenchmarkStdChaCha20Poly1305NoSSSE3(b *testing.B) {
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
