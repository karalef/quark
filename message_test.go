package quark

import (
	"bytes"
	"testing"
	"time"

	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

func TestMessage(t *testing.T) {
	ks1, err := Generate(Identity{
		Name:  "test",
		Email: "test@localhost",
	}, Scheme{
		Cert: sign.Dilithium2,
		Sign: sign.Dilithium3,
		KEM:  kem.Kyber512,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	ks2, err := Generate(Identity{
		Name:  "test2",
		Email: "test2@localhost",
	}, Scheme{
		Cert: sign.Dilithium5AES,
		Sign: sign.Dilithium2AES,
		KEM:  kem.Frodo640Shake,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := bytes.NewReader([]byte("some message"))
	sent, err := NewMessage(plaintext, ks2.Public(), ks1, MessageOpts{})
	if err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	out, err := pack.ArmoredEncoder(buf, sent.PacketTag().BlockType(), nil)
	err = pack.Pack(out, sent)
	if err != nil {
		t.Fatal(err)
	}
	err = out.Close()
	if err != nil {
		t.Fatal(err)
	}

	t.Log("\n", buf.String())

	received := new(Message)
	in, err := pack.DecodeArmored(buf)
	if err != nil {
		t.Fatal(err)
	}
	err = pack.UnpackExact(in.Body, received)
	if err != nil {
		t.Fatal(err)
	}

	receivedPlaintext := new(bytes.Buffer)
	err = DecryptMessage(receivedPlaintext, received, ks2, ks1.Public())
	if err != nil {
		t.Fatal(err)
	}

	t.Log("symmetric:", received.Header.Encryption.Symmetric.Scheme.String())
	t.Log("signature verified:", ks1.Identity().String(), time.Unix(received.Header.Time, 0))
	t.Log("message integrity verified")
	t.Log(receivedPlaintext.String())
}
