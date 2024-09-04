package message

import (
	"bytes"
	"testing"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/pack"
)

func TestMessage(t *testing.T) {
	_, sk, _, _, err := test_create(sign.EDDilithium3, kem.Kyber768)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, _, err = test_create(sign.EDDilithium2, kem.Kyber1024)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := bytes.NewReader([]byte("some message"))
	sent, err := New(plaintext,
		WithSignature(sk),
		WithCompression(compress.LZ4, 0, compress.LZ4Opts{Threads: 4}),
		WithPassword("password", password.Build(aead.Build(cipher.AESCTR256, mac.BLAKE3), kdf.Argon2i), kdf.Cost{
			CPU:         2,
			Memory:      64 * 1024,
			Parallelism: 4,
		}))
	if err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	out, err := pack.ArmoredEncoder(buf, sent.PacketTag().BlockType(), nil)
	if err != nil {
		t.Fatal(err)
	}
	stock, encoded := len("some message"), buf.Len()
	err = pack.Pack(out, sent)
	if err != nil {
		t.Fatal(err)
	}
	err = out.Close()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("\n", buf.String())

	in, err := pack.DecodeArmored(buf)
	if err != nil {
		t.Fatal(err)
	}
	unpacked, err := pack.Unpack(in.Body)
	if err != nil {
		t.Fatal(err)
	}
	if unpacked.PacketTag() != PacketTagMessage {
		t.Fatal("invalid packet")
	}

	received := unpacked.(*Message)

	receivedPlaintext := new(bytes.Buffer)
	//err = received.Decrypt(receivedPlaintext, ksk2, sk.Public())
	received.PasswordDecrypt(receivedPlaintext, sk.Public(), "password")
	if err != nil {
		t.Fatal(err)
	}

	//t.Log("kem:", ksk2.Scheme().Name())
	t.Log("password ecnryption:", received.Header.Encryption.Symmetric.Scheme.Name(), "with", received.Header.Encryption.Symmetric.Password.KDF.Name())
	//t.Log("symmetric:", received.Header.Encryption.Symmetric.Scheme.String())
	issuer := received.Auth.Signature.Issuer
	t.Log("signed with:", sk.Scheme().Name(), issuer)
	t.Log("signature verified:", issuer.ID(), "=", received.Header.Sender, time.Unix(received.Header.Time, 0))
	t.Log("message integrity verified")
	t.Log("compression:", received.Header.Compression.Name())
	t.Log("size overhead (%):", float64(encoded)/float64(stock)*100)
	t.Log(receivedPlaintext.String())
}

func test_create(scheme sign.Scheme, kemScheme kem.Scheme) (*quark.Identity, quark.PrivateKey, kem.PrivateKey, kem.PublicKey, error) {
	id, sk, err := quark.Generate(scheme, 0)
	if err != nil {
		return id, sk, nil, nil, err
	}

	ksk, kpk, err := kem.Generate(kemScheme, nil)
	if err != nil {
		return id, sk, nil, nil, err
	}

	return id, sk, ksk, kpk, nil
}
