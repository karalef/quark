// package subkey implements subkey certificate type as a binding for a key.
package subkey

import (
	"github.com/karalef/quark"
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/pke"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// Sign subkey certificate type.
const CertTypeSignSubkey = quark.CertTypeKey + ".subkey.sign"

// KEM subkey certificate type.
const CertTypeKEMSubkey = quark.CertTypeKey + ".subkey.kem"

// PKE subkey certificate type.
const CertTypePKESubkey = quark.CertTypeKey + ".subkey.pke"

// PacketTagSubkey is a subkey packet tag.
const PacketTagSubkey pack.Tag = 0x06

func init() {
	pack.RegisterPacketType(pack.NewType((*Subkey)(nil), "subkey"))
}

// GenerateSign generates a new sign subkey.
func GenerateSign(s sign.Scheme) (*Subkey, sign.PrivateKey, error) {
	sk, pk, err := sign.Generate(s, nil)
	if err != nil {
		return nil, nil, err
	}
	return New(pk), sk, nil
}

// GenerateKEM generates a new KEM subkey.
func GenerateKEM(s kem.Scheme) (*Subkey, kem.PrivateKey, error) {
	sk, pk, err := kem.Generate(s, nil)
	if err != nil {
		return nil, nil, err
	}
	return New(pk), sk, nil
}

// GeneratePKE generates a new PKE subkey.
func GeneratePKE(s pke.Scheme) (*Subkey, pke.PrivateKey, error) {
	sk, pk, err := pke.Generate(s, nil)
	if err != nil {
		return nil, nil, err
	}
	return New(pk), sk, nil
}

// New creates a new subkey.
func New(pk crypto.Key) *Subkey {
	cert := quark.NewCertificate(NewPublicKey(pk))
	return FromCertificate(&cert)
}

// FromRaw creates a subkey from a raw certificate.
func FromRaw(c quark.Raw) (*Subkey, error) {
	cert, err := quark.As[PublicKey](c)
	if err != nil {
		return nil, err
	}
	return FromCertificate(&cert), nil
}

// FromCertificate creates a subkey from a certificate.
func FromCertificate(c *quark.Certificate[PublicKey]) *Subkey {
	return (*Subkey)(c)
}

// Subkey represents a subkey certificate.
type Subkey quark.Certificate[PublicKey]

// PacketTag implements pack.Packable interface.
func (*Subkey) PacketTag() pack.Tag { return PacketTagSubkey }

// Key returns public key.
func (k Subkey) Key() crypto.Key { return k.Data.Key() }

// ID returns key ID.
func (k Subkey) KeyID() crypto.ID { return k.Data.ID() }

// Fingerprint returns key fingerprint.
func (k Subkey) Fingerprint() crypto.Fingerprint { return k.Data.Fingerprint() }

// Validity returns key validity.
func (k Subkey) Validity() quark.Validity { return k.Signature.Validity }

// Certificate returns key as a certificate.
func (k *Subkey) Certificate() *quark.Certificate[PublicKey] {
	return (*quark.Certificate[PublicKey])(k)
}

// NewPublicKey creates a new public key.
func NewPublicKey(pk crypto.Key) PublicKey {
	return PublicKey{PublicKey: quark.NewPublicKey(pk)}
}

var _ quark.CertData[PublicKey] = PublicKey{}

// PublicKey represents a public key as a certificate data.
type PublicKey struct{ quark.PublicKey[crypto.Key] }

// CertPacketTag returns certificate packet tag.
func (PublicKey) CertPacketTag() pack.Tag { return PacketTagSubkey }

// CertType returns certificate type.
func (pk PublicKey) CertType() string {
	k := pk.PublicKey.Key()
	if _, ok := k.(sign.PublicKey); ok {
		return CertTypeSignSubkey
	} else if _, ok := k.(kem.PublicKey); ok {
		return CertTypeKEMSubkey
	} else if _, ok := k.(pke.PublicKey); ok {
		return CertTypePKESubkey
	}
	panic("unknown key type")
}

// Copy returns a copy of the public key.
func (pk PublicKey) Copy() PublicKey { return pk }
