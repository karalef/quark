package quark

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/pack"
)

// Generate generates a new keyset from scheme using crypto/rand.
func Generate(id Identity, scheme Scheme, expires int64) (Private, error) {
	certSeed := crypto.Rand(scheme.Cert.SeedSize())
	signSeed := crypto.Rand(scheme.Sign.SeedSize())
	kemSeed := crypto.Rand(scheme.KEM.SeedSize())

	return newPrivate(id, scheme, expires, certSeed, signSeed, kemSeed)
}

// Derive deterministically creates a new keyset from scheme using provided seeds.
func Derive(id Identity, scheme Scheme, expires int64, certSeed []byte, signSeed []byte, kemSeed []byte) (Private, error) {
	return newPrivate(id, scheme, expires, certSeed, signSeed, kemSeed)
}

// PasswordParams represents a parameters for
// deterministically keyset derivation from password.
type PasswordParams struct {
	KDF       kdf.KDF
	KDFParams kdf.Params
	XOF       xof.XOF
	Password  string
	Salt      []byte
}

// Certify creates a certification signature for the ks.
func Certify(with Private, ks Public) error {
	if with.ID() == ks.ID() {
		return errors.New("keyset cannot certify itself")
	}
	return ks.pub().sign(with)
}

// Identity contains the keyset owner's identity.
type Identity struct {
	Name    string `msgpack:"name"`
	Email   string `msgpack:"email,omitempty"`
	Comment string `msgpack:"comment,omitempty"`
}

// IsValid returns true if the UserID is valid.
func (id Identity) IsValid() bool { return id.Name != "" }

func (id Identity) String() string {
	str := id.Name
	if id.Email != "" {
		str += " <" + id.Email + ">"
	}
	if id.Comment != "" {
		str += " (" + id.Comment + ")"
	}
	return str
}

// Validity contains the validity info of the keyset.
type Validity struct {
	// keyset creation time
	Created int64 `msgpack:"created"`
	// keyset expiration time
	Expires int64 `msgpack:"expires"`
	// keyset revocation time
	Revoked int64 `msgpack:"revoked"`
	// keyset revocation reason
	Reason string `msgpack:"reason"`
}

// ErrInvalidIdentity is returned if the identity is invalid.
var ErrInvalidIdentity = errors.New("invalid identity")

// Keyset represents a keyset.
type Keyset interface {
	pack.Packable

	// ID returns the ID of the keyset.
	ID() ID

	// Fingerprint returns the fingerprint of the keyset.
	Fingerprint() Fingerprint

	// Scheme returns the scheme of the keyset.
	Scheme() Scheme

	// Identity returns the identity of the keyset.
	Identity() Identity

	// Validity returns the validity of the keyset.
	Validity() Validity

	// SelfSignature returns the self-signatures.
	SelfSignature() CertificationSignature

	// Signatures returns certification signatures.
	Signatures() []CertificationSignature

	pub() *public
}

// Public represents a public keyset.
type Public interface {
	Keyset

	// Cert returns the certification public key.
	// It is used to certificate other keysets and self-sign the keyset.
	Cert() sign.PublicKey

	// Sign returns the signature public key.
	Sign() sign.PublicKey

	// KEM returns the KEM public key.
	KEM() kem.PublicKey
}

// Private represents a private keyset.
type Private interface {
	Keyset

	// Public returns the public keyset.
	Public() Public

	// ChangeIdentity changes the identity of the keyset.
	ChangeIdentity(Identity) error

	// ChangeExpiry changes the expiry of the keyset.
	ChangeExpiry(expiry int64) error

	// Revoke revokes the keyset.
	Revoke(reason string) error

	// Cert returns the certification private key.
	// It is used to certificate other keysets and self-sign the keyset.
	Cert() sign.PrivateKey

	// Sign returns the signature public key.
	Sign() sign.PrivateKey

	// KEM returns the KEM public key.
	KEM() kem.PrivateKey

	priv() *private
}

// id sizes.
const (
	IDSize       = 8          // 8
	IDStringSize = IDSize * 2 // hexed id (16)
)

// IDFromString parses hexed keyset ID.
// It returns false if the string is not a valid keyset ID.
func IDFromString(strID string) (id ID, ok bool) {
	if len(strID) != IDStringSize {
		return
	}
	_, err := hex.Decode(id[:], []byte(strID))
	return id, err == nil
}

// IDFromUint converts uint64 to ID.
func IDFromUint(uintID uint64) (id ID) {
	binary.LittleEndian.PutUint64(id[:], uintID)
	return
}

// ID represents the keyset ID.
type ID [IDSize]byte

// IsEmpty returns true if ID is empty.
func (id ID) IsEmpty() bool {
	return id == ID{}
}

func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// Uint returns keyset ID as uint64 in little endian order.
func (id ID) Uint() uint64 {
	return binary.LittleEndian.Uint64(id[:])
}

// fp sizes.
const (
	FPSize       = 32                      // sha3-256 output
	FPStringSize = FPSize*2 + FPSize/2 - 1 // 79
)

// FingerprintFromString parses string keyset fingerprint.
func FingerprintFromString(strFP string) (fp Fingerprint, ok bool) {
	if len(strFP) != FPStringSize {
		return
	}
	strFP = strings.ReplaceAll(strFP, ":", "")
	_, err := hex.Decode(fp[:], []byte(strFP))
	return fp, err == nil
}

// Fingerprint represents keyset fingerprint.
type Fingerprint [FPSize]byte

// IsEmpty returns true if fingerprint is empty.
func (f Fingerprint) IsEmpty() bool {
	return f == Fingerprint{}
}

// ID calculates keyset ID from fingerprint.
func (f Fingerprint) ID() ID {
	return ID(f[FPSize-IDSize:])
}

func (f Fingerprint) String() string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, FPStringSize+1)
	for i := 0; i < len(f); i++ {
		buf = append(buf, hex[f[i]>>4], hex[f[i]&0xf])
		i++
		buf = append(buf, hex[f[i]>>4], hex[f[i]&0xf], ':')
	}
	return string(buf[:len(buf)-1])
}
