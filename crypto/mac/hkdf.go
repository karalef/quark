package mac

// Extract extracts the PRK for the provided secret and salt using HKDF.
// MAC scheme must be hash-based.
func Extract(hmac Scheme, secret, salt []byte) []byte {
	ext := hmac.New(salt)
	ext.Write(secret)
	return ext.Tag(nil)
}

// Expand expands a presudo-random key with info into a key of the provided
// length using HKDF.
// MAC scheme must be hash-based.
// Panics if length is bigger than hmac.Size()*255.
func Expand(hmac Scheme, prk, info []byte, length uint) []byte {
	bs := uint(hmac.Size())
	blocks := uint8(length / bs)
	if length%bs > 0 {
		blocks++
	}
	if blocks == 0 || blocks > 255 {
		panic("invalid key size")
	}

	out := make([]byte, 0, uint(blocks)*bs)
	exp := hmac.New(prk)

	for counter := uint8(1); counter <= blocks; counter++ {
		if counter > 1 {
			exp.Reset()
			exp.Write(out[len(out)-int(bs):])
		}
		exp.Write(info)
		exp.Write([]byte{counter})
		out = exp.Tag(out)
	}

	return out
}
