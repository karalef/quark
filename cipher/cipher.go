package cipher

import "errors"

type Algorithm string

const (
	AESGCM128         Algorithm = "AESGCM128"
	AESGCM192         Algorithm = "AESGCM192"
	AESGCM256         Algorithm = "AESGCM256"
	XChacha20Poly1305 Algorithm = "XCHACHA20POLY1305"
)

func ListAll() []Scheme {
	a := make([]Scheme, 0, len(schemes))
	for _, v := range schemes {
		a = append(a, v)
	}
	return a
}

var schemes = map[Algorithm]Scheme{
	AESGCM128:         aesgcm128Scheme,
	AESGCM192:         aesgcm192Scheme,
	AESGCM256:         aesgcm256Scheme,
	XChacha20Poly1305: xchacha20poly1305Scheme,
}

func (alg Algorithm) Alg() Algorithm { return alg }

func (alg Algorithm) Scheme() Scheme {
	return schemes[alg]
}

func (alg Algorithm) IsValid() bool {
	return alg.Scheme() != nil
}

func (alg Algorithm) String() string {
	if !alg.IsValid() {
		return "INVALID"
	}
	return string(alg)
}

func LoadKey(key []byte, alg Algorithm) (Cipher, error) {
	scheme := alg.Scheme()
	if scheme == nil {
		return nil, ErrInvalidKeyAlgorithm
	}
	return scheme.Unpack(key)
}

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

type Scheme interface {
	Alg() Algorithm
	KeySize() int
	NonceSize() int
	Overhead() int

	Unpack(key []byte) (Cipher, error)
}

var _ Scheme = baseScheme{}

type baseScheme struct {
	Algorithm
	keySize   int
	nonceSize int
	overhead  int
	unpack    func(key []byte) (Cipher, error)
}

func (s baseScheme) KeySize() int                      { return s.keySize }
func (s baseScheme) NonceSize() int                    { return s.nonceSize }
func (s baseScheme) Overhead() int                     { return s.overhead }
func (s baseScheme) Unpack(key []byte) (Cipher, error) { return s.unpack(key) }

// errors
var (
	ErrInvalidKeyAlgorithm = errors.New("invalid cipher algorithm")
)
