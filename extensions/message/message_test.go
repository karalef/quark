package message

import (
	"bytes"
	"testing"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/encrypted/secret"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/pack"
)

func TestMessage(t *testing.T) {
	_, sk, ksk, kpk, err := test_create(sign.EDDilithium3, kem.Kyber768)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	plaintext := bytes.NewReader([]byte("some message"))
	sent, err := New(plaintext,
		WithSignature(sk, now.AddDate(1, 0, 0).Unix()),
		WithCompression(compress.LZ4, 0, compress.LZ4Opts{Threads: 4}),
		WithEncryption(kpk, secret.Build(aead.ChaCha20Poly1305, xof.BLAKE3x)),
		WithFileInfo(FileInfo{
			Name:     "test.txt",
			Created:  now.AddDate(-1, 0, 0).Unix(),
			Modified: now.Unix(),
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	err = pack.PackArmored(buf, sent, nil)
	if err != nil {
		t.Fatal(err)
	}
	stock, encoded := len("some message"), buf.Len()

	// t.Log("\n", buf.String())

	unpacked, _, err := pack.UnpackArmored(buf)
	if err != nil {
		t.Fatal(err)
	}
	if unpacked.PacketTag() != PacketTagMessage {
		t.Fatal("invalid packet")
	}

	received := unpacked.(*Message)

	receivedPlaintext := new(bytes.Buffer)
	err = received.Decrypt(receivedPlaintext, Decrypt{
		Issuer:    sk.Public(),
		Password:  "password",
		Recipient: ksk,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("kem:", ksk.Scheme().Name())

	sym := received.Header.Encryption.Symmetric
	t.Log("symmetric", sym.Secret.Secret.Name())
	// t.Log("password encryption:", sym.Passphrase.Build(sym.Scheme).Name())

	issuer := received.Auth.Signature.Issuer
	t.Log("signed with:", sk.Scheme().Name(), issuer.ID().String(), time.Unix(received.Header.Time, 0))
	t.Log("compression:", received.Header.Compression.Name())
	t.Logf("transmission size overhead: %.2f%%\n", float64(encoded)/float64(stock)*100-100)
	file := received.Header.File
	t.Logf("file %s created at %s, modified at %s\n", file.Name, time.Unix(file.Created, 0), time.Unix(file.Modified, 0))
	t.Log(receivedPlaintext.String())
}

func test_create(scheme sign.Scheme, kemScheme kem.Scheme) (*quark.Key, sign.PrivateKey, kem.PrivateKey, kem.PublicKey, error) {
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
