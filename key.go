package quark

import (
	"errors"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// CertTypeKey is a certificate type for key and base for key bindings.
const CertTypeKey = "quark.key"

// Generate generates a new key using crypto/rand.
func Generate(scheme sign.Scheme, v Validity) (*Key, sign.PrivateKey, error) {
	return Derive(scheme, crypto.Rand(scheme.SeedSize()), v)
}

// Derive deterministically creates a new key and signs it.
func Derive(scheme sign.Scheme, seed []byte, v Validity) (*Key, sign.PrivateKey, error) {
	sk, pk, err := scheme.DeriveKey(seed)
	if err != nil {
		return nil, nil, err
	}

	cert := NewCertificate(NewKeyData(pk))
	if err = cert.Sign(sk, v); err != nil {
		return nil, nil, err
	}

	return KeyFromCertificate(&cert), sk, nil
}

// KeyFromRaw creates a key from a raw certificate.
func KeyFromRaw(c Raw) (*Key, error) {
	cert, err := As[KeyData](c)
	if err != nil {
		return nil, err
	}
	return KeyFromCertificate(&cert), nil
}

// KeyFromCertificate converts certificate to key.
func KeyFromCertificate(c *Certificate[KeyData]) *Key { return (*Key)(c) }

// Key represents a key certificate.
type Key Certificate[KeyData]

// PacketTag implements pack.Packable interface.
func (k *Key) PacketTag() pack.Tag { return k.Certificate().PacketTag() }

// Key returns public key.
func (k Key) Key() sign.PublicKey { return k.Data.Key() }

// KeyID returns key ID.
func (k Key) KeyID() crypto.ID { return k.Data.ID() }

// Fingerprint returns key fingerprint.
func (k Key) Fingerprint() crypto.Fingerprint { return k.Data.Fingerprint() }

// Certificate returns key as a certificate.
func (k *Key) Certificate() *Certificate[KeyData] { return (*Certificate[KeyData])(k) }

// Copy creates a full independent copy of the key.
func (k *Key) Copy() *Key { cp := k.Certificate().Copy(); return KeyFromCertificate(&cp) }

// CorrespondsTo returns true if key corresponds to given private key.
func (k Key) CorrespondsTo(sk sign.PrivateKey) bool { return sign.CorrespondsTo(k.Key(), sk) }

// Validity returns key validity.
func (k *Key) Validity() Validity { return k.Signature.Validity }

// SetValidity sets key validity.
// If the key is not signed, creates a self-signature.
func (k *Key) SetValidity(sk sign.PrivateKey, v Validity) error {
	return k.Sign(sk, k.Certificate(), v)
}

// Verify verifies the specified signature created by this key.
func (k Key) Verify(s Signable, sig Signature) error {
	if sig.Issuer != k.Fingerprint() {
		return errors.New("wrong issuer")
	}
	ok, err := sig.VerifyObject(k.Key(), s)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("wrong signature")
	}
	return nil
}

// Sign signs the certificate using corresponding private key and checking the
// key validity.
func (k Key) Sign(sk sign.PrivateKey, c Any, v Validity) error {
	if !k.CorrespondsTo(sk) {
		return crypto.ErrKeyNotCorrespond
	}
	if !k.Validity().IsValid(v.Created) {
		return ErrExpiredOrRevoked
	}
	return c.Sign(sk, v)
}

// NewKeyData creates a new key data.
func NewKeyData(pk sign.PublicKey) KeyData {
	return KeyData{PublicKey: NewPublicKey(pk)}
}

var _ Certifyable[KeyData] = KeyData{}

// KeyData represents a public key as a certificate data.
type KeyData struct{ PublicKey[sign.PublicKey] }

// CertPacketTag returns certificate packet tag.
func (KeyData) CertPacketTag() pack.Tag { return PacketTagKey }

// CertType returns certificate type.
func (KeyData) CertType() string { return CertTypeKey }

// Copy returns a copy of the public key.
func (kd KeyData) Copy() KeyData { return kd }
