package crypto

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/pkg/crockford"
	"github.com/karalef/quark/scheme"
)

// id sizes.
const (
	IDSize       = 8                                   // 8
	IDStringSize = IDSize/5*8 + (IDSize%5*8+4)/5       // 13; base32 encoded
	FPSize       = 32                                  // 32; sha3-256 output
	fpStringSize = FPSize/5*8 + (FPSize%5*8+4)/5       // 52; base32 encoded
	FPStringSize = fpStringSize + (fpStringSize/4-1)*2 // 76; base32 encoded and parted
)

// IDFromString parses encoded key ID.
// It returns false if the string is not a valid key ID.
func IDFromString(strID string) (id ID, ok bool) {
	if len(strID) != IDStringSize {
		return
	}
	_, err := crockford.Upper.Decode(id[:], []byte(strID))
	return id, err == nil
}

// IDFromUint converts uint64 to ID.
func IDFromUint(uintID uint64) (id ID) {
	binary.LittleEndian.PutUint64(id[:], uintID)
	return
}

// ID represents the key ID.
type ID [IDSize]byte

// IsEmpty returns true if ID is empty.
func (id ID) IsEmpty() bool { return id == ID{} }

// Bytes returns key ID as bytes.
func (id ID) Bytes() []byte { return id[:] }

func (id ID) String() string {
	return crockford.Upper.EncodeToString(id[:])
}

// Uint returns key ID as uint64 in little endian order.
func (id ID) Uint() uint64 {
	return binary.LittleEndian.Uint64(id[:])
}

// FingerprintFromString parses string key fingerprint.
func FingerprintFromString(strFP string) (fp Fingerprint, ok bool) {
	if len(strFP) != FPStringSize {
		return
	}
	strFP = strings.ReplaceAll(strFP, "::", "")
	_, err := crockford.Upper.Decode(fp[:], []byte(strFP))
	return fp, err == nil
}

// Fingerprint represents the key fingerprint.
type Fingerprint [FPSize]byte

// IsEqual returns true if fingerprints are equal.
func (f Fingerprint) IsEqual(o Fingerprint) bool {
	return subtle.ConstantTimeCompare(f[:], o[:]) == 1
}

// IsEmpty returns true if fingerprint is empty.
func (f Fingerprint) IsEmpty() bool { return f == Fingerprint{} }

// ID calculates ID from fingerprint.
func (f Fingerprint) ID() ID { return ID(f[FPSize-IDSize:]) }

// Bytes returns fingerprint as bytes.
func (f Fingerprint) Bytes() []byte { return f[:] }

func (f Fingerprint) String() string {
	enc := make([]byte, crockford.Upper.EncodedLen(len(f)))
	crockford.Upper.Encode(enc, f[:])
	buf := make([]byte, 0, len(enc)+len(enc)/2)
	for i := 0; i < len(enc); i += 4 {
		buf = append(buf, enc[i:i+4]...)
		buf = append(buf, ':', ':')
	}
	return string(buf[:len(buf)-2])
}

// CalculateFingerprint calculates the fingerprint of the given scheme and public key.
func CalculateFingerprint(scheme string, publicKey []byte) (fp Fingerprint) {
	sha3 := hash.SHA3.New()
	sha3.Write([]byte(strings.ToUpper(scheme)))
	sha3.Write([]byte{':'})
	sha3.Write(publicKey)
	sha3.Sum(fp[:0])
	return
}

// Scheme is a basic interface for asymmetric algorithm schemes.
type Scheme interface {
	scheme.Scheme

	// Size of packed public keys.
	PublicKeySize() int

	// Size of packed private keys.
	PrivateKeySize() int

	// Size of seed.
	SeedSize() int
}

// NewKeyID creates a new key ID from the given public key.
// It DOES NOT returns the pointer, but the KeyID requires to be a pointer
// or be inside a struct with pointer receiver.
func NewKeyID[PublicKey RawKey](k PublicKey) KeyID[PublicKey] {
	return KeyID[PublicKey]{PublicKey: k}
}

// KeyID is an extension of public key to support key ID.
type KeyID[PublicKey RawKey] struct {
	PublicKey PublicKey
	id        ID
	fp        Fingerprint
}

func (k KeyID[PublicKey]) Scheme() Scheme { return k.PublicKey.Scheme() }
func (k KeyID[PublicKey]) Pack() []byte   { return k.PublicKey.Pack() }

// ID returns the key ID.
func (k *KeyID[PublicKey]) ID() ID {
	if k.id.IsEmpty() {
		k.id = k.Fingerprint().ID()
	}
	return k.id
}

// Fingerprint returns the key fingerprint.
func (k *KeyID[PublicKey]) Fingerprint() Fingerprint {
	if k.fp.IsEmpty() {
		k.fp = CalculateFingerprint(k.PublicKey.Scheme().Name(), k.PublicKey.Pack())
	}
	return k.fp
}

// RawKey is a basic interface for asymmetric keys without key ID support.
type RawKey interface {
	// Scheme returns the scheme.
	Scheme() Scheme

	// Pack allocates a new slice of bytes with Scheme().{Private, Public}KeySize() length
	// and writes the key to it.
	Pack() []byte
}

// Key is a basic interface for asymmetric keys.
type Key interface {
	// ID returns the key ID.
	ID() ID

	// Fingerprint returns the key fingerprint.
	Fingerprint() Fingerprint

	RawKey
}

// Corresponds returns true if k1 and k2 have the same fingerprint.
func Corresponds(k1, k2 Key) bool {
	return k1.Fingerprint().IsEqual(k2.Fingerprint())
}

// key errors.
var (
	ErrKeyNotCorrespond = errors.New("the public key does not correspond to the private key")
)
