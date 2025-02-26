package compress

import (
	"bytes"
	"io"
	"testing"
)

func TestCompress(t *testing.T) {
	testData := bytes.Repeat([]byte("data to be compressed"), 64)

	cmp, err := ByName("lz4")
	if err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	wc, err := cmp.Compress(buf, cmp.MaxLevel(), LZ4Opts{
		Threads: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := wc.Write(testData)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testData) {
		t.Fatal(io.ErrShortWrite)
	}
	err = wc.Close()
	if err != nil {
		t.Fatal(err)
	}

	decompressed := bytes.NewBuffer(make([]byte, 0, len(testData)))
	r, err := cmp.Decompress(buf, LZ4Opts{
		Threads: 4,
	})
	_, err = io.Copy(decompressed, r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(testData, decompressed.Bytes()) {
		t.Fatal("unexpected data")
	}
}
