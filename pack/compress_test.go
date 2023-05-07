package pack

import (
	"bytes"
	"io"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/karalef/quark/internal"
)

func TestCompress(t *testing.T) {
	rnd := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	d, _ := internal.RandRead(rnd, 512)

	buf := new(bytes.Buffer)
	wc, err := Compress(buf, Flate, BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	_, err = wc.Write(d)
	if err != nil {
		t.Fatal(err)
	}
	err = wc.Close()
	if err != nil {
		t.Fatal(err)
	}

	r, err := Decompress(buf, Flate)
	if err != nil {
		t.Fatal(err)
	}

	d2, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(d, d2) {
		t.Fatal("unexpected data")
	}
}
