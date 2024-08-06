package message

import (
	"bytes"
	"testing"
	"time"

	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/encaps"
	"github.com/karalef/quark/pack"
)

func TestMessage(t *testing.T) {
	_, sk, _, _, err := test_create("karalef", sign.EDDilithium3, kem.Kyber768)
	if err != nil {
		t.Fatal(err)
	}

	_, _, ksk2, kpk2, err := test_create("test", sign.EDDilithium2, kem.Kyber1024)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := bytes.NewReader([]byte("some message"))
	sent, err := New(plaintext, WithEncryption(kpk2), WithSignature(sk))
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
	err = received.Decrypt(receivedPlaintext, ksk2, sk.Public())
	if err != nil {
		t.Fatal(err)
	}

	t.Log("kem:", ksk2.Scheme().Name())
	t.Log("symmetric:", received.Header.Encryption.Symmetric.Scheme.String())
	issuer := received.Auth.Signature.Issuer
	t.Log("signed with:", sk.Scheme().Name(), issuer)
	t.Log("signature verified:", issuer.ID(), "=", received.Header.Sender, time.Unix(received.Header.Time, 0))
	t.Log("message integrity verified")
	t.Log(receivedPlaintext.String())
}

func test_create(name string, scheme sign.Scheme, kem kem.Scheme) (quark.Identity, quark.PrivateKey, encaps.PrivateKey, encaps.PublicKey, error) {
	id, sk, err := quark.Generate(scheme, 0)
	if err != nil {
		return id, sk, nil, nil, err
	}

	kpk, ksk, err := encaps.Generate(kem)
	if err != nil {
		return id, sk, nil, nil, err
	}

	return id, sk, ksk, kpk, nil
}
