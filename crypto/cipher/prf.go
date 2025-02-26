package cipher

// NewPRF creates a new stream cipher based pseudo-random function.
func NewPRF(scheme Scheme, iv, key []byte) PRF {
	return PRF{scheme.New(key, iv)}
}

// PRF is a stream cipher based pseudo-random function.
type PRF struct{ c Cipher }

// ReadE is the same as Read but returns nothing.
func (p PRF) ReadE(dst []byte) { p.c.XORKeyStream(dst, dst) }

// Read implements the io.Reader interface.
func (p PRF) Read(dst []byte) (int, error) {
	p.c.XORKeyStream(dst, dst)
	return len(dst), nil
}
