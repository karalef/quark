package pack

import (
	"bytes"
	"io"
	"testing"
)

func TestPassphrased(t *testing.T) {
	const passphrase = "Test this password"
	const testdata = "Test this unencrypted data"

	buf := bytes.NewBuffer(make([]byte, 0, 2048))

	w, err := Passphrased(buf, passphrase, nil)
	if err != nil {
		t.Fatal(err)
	}

	io.WriteString(w, testdata)

	r, err := PassphrasedDecrypter(buf, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(b))

	if string(b) != testdata {
		t.Fatal("unexpected data")
	}
}
