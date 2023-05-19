package kem

import (
	"io"

	"github.com/karalef/quark/internal"
	"github.com/karalef/quark/kem/cipher"
)

func init() {
	for a, scheme := range schemes {
		if scheme.SharedSecretSize() != scheme.Cipher().KeySize() {
			panic("kem: shared key size mismatch (" + a + ")")
		}
	}
}

// Algorithm type.
type Algorithm string

// available KEM algorithms.
const (
	Kyber512AESGCM            Algorithm = "KYBER512-AES_GCM"
	Kyber512XChaCha20Poly1305 Algorithm = "KYBER512-XCHACHA20_POLY1305"

	Kyber768AESGCM            Algorithm = "KYBER768-AES_GCM"
	Kyber768XChaCha20Poly1305 Algorithm = "KYBER768-XCHACHA20_POLY1305"

	Kyber1024AESGCM            Algorithm = "KYBER1024-AES_GCM"
	Kyber1024XChaCha20Poly1305 Algorithm = "KYBER1024-XCHACHA20_POLY1305"

	Frodo640ShakeAESGCM Algorithm = "FRODO640SHAKE-AES_GCM"
)

// ListAll returns all available KEM schemes.
func ListAll() []Scheme {
	a := make([]Scheme, 0, len(schemes))
	for _, v := range schemes {
		a = append(a, v)
	}
	return a
}

var schemes = map[Algorithm]Scheme{
	Kyber512AESGCM:             kyber512aesgcmScheme,
	Kyber512XChaCha20Poly1305:  kyber512XChaCha20Poly1305Scheme,
	Kyber768AESGCM:             kyber768AESGCMScheme,
	Kyber768XChaCha20Poly1305:  kyber768XChaCha20Poly1305Scheme,
	Kyber1024AESGCM:            kyber1024AESGCMScheme,
	Kyber1024XChaCha20Poly1305: kyber1024XChaCha20Poly1305Scheme,
	Frodo640ShakeAESGCM:        frodo640ShakeAESGCMScheme,
}

func (alg Algorithm) Alg() Algorithm { return alg }
func (alg Algorithm) Scheme() Scheme { return schemes[alg] }
func (alg Algorithm) IsValid() bool  { return alg.Scheme() != nil }

func (alg Algorithm) String() string {
	if !alg.IsValid() {
		return "INVALID"
	}
	return string(alg)
}

// Generate derives a key-pair from a seed generated by provided rand.
//
// If rand is nil, crypto/rand is used.
func Generate(s Scheme, rand io.Reader) (PrivateKey, PublicKey, error) {
	seed, err := internal.RandRead(rand, s.SeedSize())
	if err != nil {
		return nil, nil, err
	}
	priv, pub := s.DeriveKey(seed)
	return priv, pub, nil
}

// Encapsulate derives and encapsulates a shared secret generated by provided rand and
// creates a new Cipher with generated key.
//
// If rand is nil, crypto/rand is used.
func Encapsulate(pk PublicKey, rand io.Reader) ([]byte, cipher.Cipher, error) {
	seed, err := internal.RandRead(rand, pk.Scheme().EncapsulationSeedSize())
	if err != nil {
		return nil, nil, err
	}
	ct, ss := pk.Encapsulate(seed)
	ciph, err := pk.Scheme().Cipher().Unpack(ss)
	return ct, ciph, err
}

// Decapsulate decapsulates the shared secret from ciphertext and creates a new Cipher
// with decapsulated key.
func Decapsulate(sk PrivateKey, ciphertext []byte) (cipher.Cipher, error) {
	key, err := sk.Decapsulate(ciphertext)
	if err != nil {
		return nil, err
	}
	return sk.Scheme().Cipher().Unpack(key)
}

// Open decrypts and authenticates ciphertext and, if successful,
// appends the resulting plaintext to dst, returning the updated slice.
// It panics if nonce is not of length Scheme().Cipher().NonceSize().
func Open(sk PrivateKey, dst, encryptedSecret, nonce, ciphertext []byte) (plaintext []byte, err error) {
	key, err := sk.Decapsulate(encryptedSecret)
	if err != nil {
		return nil, err
	}
	ciph, err := sk.Scheme().Cipher().Unpack(key)
	if err != nil {
		return nil, err // must never happen
	}
	return ciph.Open(dst, nonce, ciphertext)
}

// Seal encrypts and authenticates plaintext and appends the result to dst,
// returning the updated slice and encrypted shared secret.
// It panics if nonce is not of length Scheme().Cipher().NonceSize()
// or if secretSeed is not of length Scheme().EncapsulationSeedSize().
func Seal(pk PublicKey, dst, secretSeed, nonce, plaintext []byte) (ciphertext, ecnryptedSecret []byte) {
	ecnryptedSecret, key := pk.Encapsulate(secretSeed)
	ciph, err := pk.Scheme().Cipher().Unpack(key)
	if err != nil {
		panic(err)
	}
	return ciph.Seal(dst, nonce, plaintext), ecnryptedSecret
}

// Scheme represents a KEM scheme.
type Scheme interface {
	Alg() Algorithm

	// Cipher returns cipher scheme.
	Cipher() cipher.Scheme

	// DeriveKey derives a key-pair from a seed.
	//
	// Panics if seed is not of length SeedSize().
	DeriveKey(seed []byte) (PrivateKey, PublicKey)

	// Unpacks a PublicKey from the provided bytes.
	UnpackPublic(key []byte) (PublicKey, error)

	// Unpacks a PrivateKey from the provided bytes.
	UnpackPrivate(key []byte) (PrivateKey, error)

	// Size of packed public keys.
	PublicKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of encapsulated shared secret.
	CiphertextSize() int

	// Size of shared secret.
	SharedSecretSize() int

	// Size of encapsulation seed.
	EncapsulationSeedSize() int

	// Size of seed.
	SeedSize() int
}

// PrivateKey represents a KEM private key.
type PrivateKey interface {
	Scheme() Scheme

	Equal(PrivateKey) bool

	// Bytes allocates a new slice of bytes with Scheme().PrivateKeySize() length
	// and writes the private key to it.
	Bytes() []byte

	// Decapsulate decapsulates the shared secret from the provided ciphertext.
	Decapsulate(ciphertext []byte) ([]byte, error)
}

// PublicKey represents a KEM public key.
type PublicKey interface {
	Scheme() Scheme

	Equal(PublicKey) bool

	// Bytes allocates a new slice of bytes with Scheme().PublicKeySize() length
	// and writes the public key to it.
	Bytes() []byte

	// Encapsulate encapsulates a shared secret generated from provided seed.
	// It panics if seed is not of length Scheme().SeedSize().
	Encapsulate(seed []byte) (ciphertext, secret []byte)
}
