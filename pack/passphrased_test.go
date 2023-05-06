package pack

import (
	"bytes"
	"io"
	"runtime"
	"testing"

	"github.com/karalef/quark/internal"
)

func TestPassphrased(t *testing.T) {
	const passphrase = "Test this password"
	const testdata = "Test this unencrypted data"

	iv := IV(internal.Rand(IVSize))
	salt := internal.Rand(SaltSizeRFC)

	params := Argon2Params{
		Time:    TimeRFC,
		Memory:  MemoryRFC,
		Threads: uint8(runtime.GOMAXPROCS(0)),
	}

	buf := bytes.NewBuffer(make([]byte, 0, 512))

	w := Encrypt(buf, passphrase, iv, salt, params)

	io.WriteString(w, testdata)

	r := Decrypt(buf, passphrase, iv, salt, params)

	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if string(b) != testdata {
		t.Fatal("unexpected data")
	}
}
