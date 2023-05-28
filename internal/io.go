package internal

// Copy copies b to a new slice.
func Copy(b []byte) []byte {
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}
