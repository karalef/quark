package internal

// Cipher represents authenticated cipher.
type Cipher interface {
	// Encrypt XORs each byte in the given slice with a byte from the cipher's key
	// stream and authenticates the data depending on the algorithm.
	//
	// Dst and src must overlap entirely or not at all. If len(dst) < len(src),
	// Encrypt will panic. It is acceptable to pass a dst bigger than src, and in
	// that case, Encrypt will only update dst[:len(src)] and will not touch the
	// rest of dst.
	//
	// Multiple calls to Encrypt behave as if the concatenation of the src buffers
	// was passed in a single run. That is, Cipher maintains state and does not
	// reset at each Encrypt call.
	Encrypt(dst, src []byte)

	// Decrypt is exactly the same as Encrypt but authenticates the other buffer.
	Decrypt(dst, src []byte)

	// TagSize returns the tag size in bytes.
	TagSize() int

	// Tag appends the current mac to b and returns the resulting slice.
	// It does not change the underlying MAC state.
	Tag(b []byte) []byte
}
