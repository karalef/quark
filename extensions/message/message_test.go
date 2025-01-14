package message

import (
	"bytes"
	"testing"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/extensions/message/compress"
	"github.com/karalef/quark/pack"
	"github.com/karalef/quark/pack/armor"
)

var keys = func() map[crypto.Fingerprint]pke.PrivateKey {
	keys := make(map[crypto.Fingerprint]pke.PrivateKey)
	for i := 0; i < 10; i++ {
		var scheme pke.Scheme
		switch i % 3 {
		case 0:
			scheme = pke.Kyber512
		case 1:
			scheme = pke.Kyber768
		case 2:
			scheme = pke.Kyber1024
		}
		sk, _, err := pke.Generate(scheme, nil)
		if err != nil {
			panic(err)
		}
		keys[sk.Fingerprint()] = sk
	}
	return keys
}()

func TestMessage(t *testing.T) {
	sk, _, err := sign.Generate(sign.EDDilithium3, nil)
	if err != nil {
		t.Fatal(err)
	}

	selected := func() []pke.PublicKey {
		pk := make([]pke.PublicKey, 0, 3)
		for _, sk := range keys {
			pk = append(pk, sk.Public())
		}
		return pk
	}()

	now := time.Now()
	plaintext := bytes.NewReader([]byte("some message"))
	sent, err := New(plaintext,
		WithSignature(sk, now.AddDate(1, 0, 0).Unix()),
		WithCompression(compress.LZ4, 0, compress.LZ4Opts{Threads: 4}),
		WithEncryption(EncryptFor(encrypted.BuildSecret(aead.ChaCha20Poly1305, xof.BLAKE3x), selected)),
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
	armored, err := armor.Encode(buf, sent.PacketTag().BlockType(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = pack.Pack(armored, sent)
	if err != nil {
		t.Fatal(err)
	}
	if err = armored.Close(); err != nil {
		t.Fatal(err)
	}
	stock, encoded := len("some message"), buf.Len()

	// t.Log("\n", buf.String())

	block, err := armor.Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	unpacked, err := pack.Unpack(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	if unpacked.PacketTag() != PacketTagMessage {
		t.Fatal("invalid packet")
	}

	received := unpacked.(*Message)

	receivedPlaintext := new(bytes.Buffer)
	err = received.Decrypt(receivedPlaintext, Decrypt{
		Issuer:         sk.Public(),
		GroupRecipient: keys[selected[1].Fingerprint()],
	})
	if err != nil {
		t.Fatal(err)
	}

	header := received.Header
	t.Log("symmetric", header.Encryption.Group.Scheme.Name())

	issuer := received.Auth.Signature.Issuer
	t.Log("signed with:", sk.Scheme().Name(), issuer.ID().String(), time.Unix(header.Time, 0))
	t.Log("compression:", header.Compression.Name())
	t.Logf("transmission size overhead: %.2f%%\n", float64(encoded)/float64(stock)*100-100)
	file := header.File
	t.Logf("file %s created at %s, modified at %s\n", file.Name, time.Unix(file.Created, 0), time.Unix(file.Modified, 0))
	t.Log(receivedPlaintext.String())
}
