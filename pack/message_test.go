package pack

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/karalef/quark"
)

func TestMessage(t *testing.T) {
	msg := &quark.Message{
		Key:         randBytes(16),
		Fingerprint: quark.Fingerprint(randBytes(16)),
		Signature:   randBytes(16),
		Message:     randBytes(32),
	}

	t.Logf("Message: %s", string(msg.Message))
	t.Logf("Fingerprint: %s", string(msg.Fingerprint[:]))

	buf := bytes.NewBuffer(make([]byte, 0, 2048))
	err := Message(buf, msg)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(buf.String())

	msg2, err := UnpackMessage(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Message: %s", string(msg2.Message))
	t.Logf("Fingerprint: %s", string(msg2.Fingerprint[:]))
}

func TestPackUnenc(t *testing.T) {
	msg := &quark.Message{
		Message: []byte("прикольно"),
	}

	buf := bytes.NewBuffer(make([]byte, 0, 2048))
	err := Message(buf, msg)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(buf.String())
}

func randBytes(s int) []byte {
	b := make([]byte, s)
	rand.Read(b)
	return b
}
