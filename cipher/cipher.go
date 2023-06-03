package cipher

// Cipher represents an authenticated cipher.
type Cipher interface {
	Scheme() Scheme

	// Seal encrypts and authenticates plaintext and
	// appends the result to dst, returning the updated slice.
	// The nonce must be Scheme().NonceSize() bytes long.
	Seal(dst, nonce, plaintext []byte) []byte

	// Open decrypts and authenticates ciphertext and, if successful,
	// appends the resulting plaintext to dst, returning the updated slice.
	// The nonce must be Scheme().NonceSize() bytes long.
	Open(dst, nonce, ciphertext []byte) ([]byte, error)
}

// Scheme type.
type Scheme interface {
	KeySize() int
	NonceSize() int
	Overhead() int

	Unpack(key []byte) (Cipher, error)
}

var _ Scheme = baseScheme{}

type baseScheme struct {
	keySize   int
	nonceSize int
	overhead  int
	unpack    func(key []byte) (Cipher, error)
}

func (s baseScheme) KeySize() int                      { return s.keySize }
func (s baseScheme) NonceSize() int                    { return s.nonceSize }
func (s baseScheme) Overhead() int                     { return s.overhead }
func (s baseScheme) Unpack(key []byte) (Cipher, error) { return s.unpack(key) }
