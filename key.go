package quark

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pkg/crockford"
)

// id sizes.
const (
	IDSize       = 8                                        // 8
	IDStringSize = IDSize/5*8 + (IDSize%5*8+4)/5            // 13; base32 encoded
	FPSize       = 32                                       // 32; sha3-256 output
	FPStringSize = FPSize/5*8 + (FPSize%5*8+4)/5 + 52/2 - 2 // 64; base32 encoded and parted
)

// IDFromString parses hexed key ID.
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
	sha3 := hash.SHA3_256.New()
	sha3.Write([]byte(scheme))
	sha3.Write([]byte{':'})
	sha3.Write(publicKey)
	sha3.Sum(fp[:0])
	return
}

// DeriveKey creates a new private and public key from the given scheme and seed.
// Panics if the scheme is nil.
func DeriveKey(scheme sign.Scheme, seed []byte) (*PublicKey, *PrivateKey, error) {
	sk, pk, err := scheme.DeriveKey(seed)
	if err != nil {
		return nil, nil, err
	}

	pub, priv := Keys(pk, sk)
	return pub, priv, nil
}

// Keys upgrades the given public and private keys.
// If the public key is nil, it will be given from the private key.
func Keys(pk sign.PublicKey, sk sign.PrivateKey) (*PublicKey, *PrivateKey) {
	if pk == nil {
		if sk == nil {
			return nil, nil
		}
		pk = sk.Public()
	}
	pub := &PublicKey{pk: pk}
	if sk == nil {
		return pub, nil
	}
	return pub, &PrivateKey{pk: pub, sk: sk}
}

// Pub upgrades the given public key.
func Pub(pk sign.PublicKey) *PublicKey {
	pub, _ := Keys(pk, nil)
	return pub
}

// KeyID represents a key ID extension.
type KeyID interface {
	// ID returns the key ID.
	ID() ID
	// Fingerprint returns the key fingerprint.
	Fingerprint() Fingerprint
}

// key errors.
var (
	ErrKeyNotCorrespond = errors.New("the public key does not correspond to the private key")
)

// PublicKey represents a signing public key.
type PublicKey struct {
	pk sign.PublicKey
	fp Fingerprint
	id ID
}

func (p *PublicKey) ID() ID {
	if p.id.IsEmpty() {
		p.id = p.Fingerprint().ID()
	}
	return p.id
}

func (p *PublicKey) Fingerprint() Fingerprint {
	if p.fp.IsEmpty() {
		p.fp = CalculateFingerprint(p.Scheme().Name(), p.pk.Pack())
	}
	return p.fp
}

func (p *PublicKey) Scheme() sign.Scheme {
	return p.pk.Scheme()
}

func (p *PublicKey) CorrespondsTo(sk *PrivateKey) bool {
	return p == sk.pk || p.Fingerprint() == sk.Fingerprint()
}

func (p *PublicKey) Verify(message, signature []byte) (bool, error) {
	return p.pk.Verify(message, signature)
}

func (p PublicKey) Raw() sign.PublicKey {
	return p.pk
}
