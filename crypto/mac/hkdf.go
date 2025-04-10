package mac

// NewKDF creates a KDF with the provided secret and salt.
func NewKDF(hmac Scheme, secret, salt []byte) KDF {
	prk := Extract(hmac, secret, salt)
	return KDF{hmac, prk}
}

// KDF represents an HKDF extracted PRK with a scheme.
type KDF struct {
	Scheme Scheme
	PRK    []byte
}

// Derive calls Expand with the underlying scheme and PRK.
func (k KDF) Derive(info []byte, length uint) []byte {
	return Expand(k.Scheme, k.PRK, info, length)
}

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

	return out[:length]
}

// Key derives a key of the provided length using HKDF.
// MAC scheme must be hash-based.
// Panics if length is bigger than hmac.Size()*255.
func Key(hmac Scheme, secret, salt, info []byte, length uint) []byte {
	return Expand(hmac, Extract(hmac, secret, salt), info, length)
}
