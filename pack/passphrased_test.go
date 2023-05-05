package pack

import (
	"bytes"
	"io"
	"testing"

	"github.com/karalef/quark/internal"
)

func TestPassphrased(t *testing.T) {
	const passphrase = "Test this password"
	const testdata = "Test this unencrypted data"

	iv, _ := internal.RandRead(nil, IVSize)
	salt, _ := internal.RandRead(nil, SaltSize)

	buf := bytes.NewBuffer(make([]byte, 0, 2048))

	w := Encrypt(buf, passphrase, iv, salt)

	io.WriteString(w, testdata)

	r := Decrypt(buf, passphrase, iv, salt)

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != testdata {
		t.Fatal("unexpected data")
	}
}
