package quark

import (
	"errors"
	"io"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// Generate generates a new key using crypto/rand.
func Generate(scheme sign.Scheme) (*Key, sign.PrivateKey, error) {
	return GenerateWithValidity(scheme, NewValidity(time.Now().Unix(), 0))
}

// GenerateWithValidity generates a new key using crypto/rand with given validity.
func GenerateWithValidity(scheme sign.Scheme, v Validity) (*Key, sign.PrivateKey, error) {
	return Derive(scheme, crypto.Rand(scheme.SeedSize()), v)
}

// Derive deterministically creates a new key.
// The key creation time is set to the v.Created.
func Derive(scheme sign.Scheme, seed []byte, v Validity) (*Key, sign.PrivateKey, error) {
	sk, pk, err := scheme.DeriveKey(seed)
	if err != nil {
		return nil, nil, err
	}

	key := &Key{
		pk:      pk,
		created: v.Created,
	}
	err = key.selfSign(sk, v)
	if err != nil {
		return nil, nil, err
	}

	return key, sk, nil
}

var (
	_ pack.Packable      = (*Key)(nil)
	_ pack.CustomEncoder = (*Key)(nil)
	_ pack.CustomDecoder = (*Key)(nil)
)

// Key is a signed public key with binded data and certifications.
type Key struct {
	pk             sign.PublicKey
	bindings       map[CertID]*RawCertificate
	certifications []Signature
	self           Signature
	created        int64
}

// ID returns key ID.
func (p *Key) ID() crypto.ID { return p.pk.ID() }

// Fingerprint returns key fingerprint.
func (p *Key) Fingerprint() crypto.Fingerprint { return p.pk.Fingerprint() }

// Key returns public key.
func (p *Key) Key() sign.PublicKey { return p.pk }

// CorrespondsTo returns true if key corresponds to given private key.
func (p *Key) CorrespondsTo(sk sign.PrivateKey) bool { return sign.CorrespondsTo(p.Key(), sk) }

// SelfSignature returns self-signature.
func (p *Key) SelfSignature() Signature { return p.self.Copy() }

// Validity returns key validity.
func (p *Key) Validity() (int64, Validity) {
	return p.created, p.self.Validity
}

// Verify verifies the key certification.
// It also can verify the self-signature.
func (p *Key) Verify(key sign.PublicKey, sig Signature) error {
	if key.Fingerprint() != sig.Issuer {
		return errors.New("wrong issuer")
	}
	ok, err := sig.VerifyObject(key, p)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("wrong signature")
	}
	return nil
}

// Bindings returns key bindings.
func (p *Key) Bindings() []RawCertificate {
	binds := make([]RawCertificate, 0, len(p.bindings))
	for _, bind := range p.bindings {
		binds = append(binds, bind.Copy())
	}
	return binds
}

// ErrBindingNotFound is returned if the binding is not found.
var ErrBindingNotFound = errors.New("binding not found")

func (p *Key) getBinding(id CertID) (*RawCertificate, error) {
	bind, ok := p.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	return bind, nil
}

// GetBinding returns the binding.
func (p *Key) GetBinding(id CertID) (RawCertificate, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return RawCertificate{}, err
	}
	return bind.Copy(), nil
}

// GetBinding returns the binding with constrained type.
func GetBinding[T Certifyable[T]](ident *Key, id CertID) (Certificate[T], error) {
	var empty Certificate[T]
	bind, err := ident.getBinding(id)
	if err != nil {
		return empty, err
	}
	return CertificateAs[T](bind.Copy())
}

func signBinding[T Certifyable[T]](id *Key, sk sign.PrivateKey, b *Certificate[T], v Validity) error {
	if err := id.checkKey(sk); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	return b.Sign(sk, v)
}

// Bind binds the data to the key.
func Bind[T Certifyable[T]](id *Key, sk sign.PrivateKey, expires int64, data T) (Certificate[T], error) {
	bind := NewCertificate(data)
	err := signBinding(id, sk, &bind, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return bind, err
	}
	raw := bind.Raw()
	return bind, id.addBinding(&raw)
}

// Bind binds the data to the key.
func (p *Key) Bind(sk sign.PrivateKey, expires int64, bind RawCertificate) (RawCertificate, error) {
	err := signBinding(p, sk, &bind, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return RawCertificate{}, err
	}
	cpy := bind.Copy()
	return bind, p.addBinding(&cpy)
}

func (p *Key) addBinding(bind *RawCertificate) error {
	if p.bindings == nil {
		p.bindings = make(map[CertID]*RawCertificate)
	}
	if _, err := p.GetBinding(bind.ID); err == nil {
		return errors.New("duplicate binding")
	}
	p.bindings[bind.ID] = bind
	return nil
}

// Rebind rebinds the data to the key with new expiration time.
// It does not change the binding ID.
func (p *Key) Rebind(id CertID, sk sign.PrivateKey, expires int64) (RawCertificate, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return bind.Copy(), err
	}
	now := time.Now().Unix()
	if v := bind.Validity(); !v.IsValid(now) {
		return RawCertificate{}, errors.New("binding is expired or revoked")
	}
	err = signBinding(p, sk, bind, NewValidity(now, expires))
	return bind.Copy(), err
}

// RevokeBinding revokes the binding.
func (p *Key) RevokeBinding(id CertID, sk sign.PrivateKey, reason string) (RawCertificate, error) {
	b, err := p.getBinding(id)
	if err != nil {
		return RawCertificate{}, err
	}
	err = signBinding(p, sk, b, b.Validity().Revoke(time.Now().Unix(), reason))
	return b.Copy(), err
}

// DeleteBinding deletes the expired or revoked binding.
func (p *Key) DeleteBinding(id CertID) (RawCertificate, error) {
	b, err := p.getBinding(id)
	if err != nil {
		return RawCertificate{}, err
	}
	now := time.Now().Unix()
	if v := b.Validity(); v.IsValid(now) {
		return b.Copy(), errors.New("binding is not expired or revoked")
	}
	delete(p.bindings, id)
	return b.Copy(), nil
}

// Certifications returns certification signatures.
func (p *Key) Certifications() []Signature {
	certs := make([]Signature, len(p.certifications))
	for i, cert := range p.certifications {
		certs[i] = cert.Copy()
	}
	return certs
}

// Certify signs the key.
func (p *Key) Certify(with sign.PrivateKey, expires int64) error {
	if p.CorrespondsTo(with) {
		return errors.New("the key cannot certify itself")
	}
	sig, err := SignObject(with, NewValidity(time.Now().Unix(), expires), p)
	if err != nil {
		return err
	}
	p.certifications = append(p.certifications, sig)
	return nil
}

// ChangeExpiry changes the expiration time of the key.
func (p *Key) ChangeExpiry(sk sign.PrivateKey, expiry int64) error {
	return p.selfSign(sk, NewValidity(time.Now().Unix(), expiry))
}

// Revoke revokes the key.
func (p *Key) Revoke(sk sign.PrivateKey, reason string) error {
	if p.self.Validity.IsRevoked() {
		return errors.New("the key is already revoked")
	}
	now := time.Now().Unix()
	return p.selfSign(sk, p.self.Validity.Revoke(now, reason))
}

// SignEncode implements Signable.
func (p *Key) SignEncode(w io.Writer) error {
	key := p.Key()
	_, err := w.Write([]byte(key.Scheme().Name()))
	if err != nil {
		return err
	}
	_, err = w.Write(key.Pack())
	if err != nil {
		return err
	}
	_, err = w.Write(MarshalTime(p.created))
	return err
}

// ErrExpiredOrRevoked is returned if the key is expired or revoked.
var ErrExpiredOrRevoked = errors.New("key is expired or revoked")

func (p *Key) checkKey(sk sign.PrivateKey) error {
	if v := p.self.Validity; !v.IsValid(time.Now().Unix()) {
		return ErrExpiredOrRevoked
	}
	if !p.CorrespondsTo(sk) {
		return crypto.ErrKeyNotCorrespond
	}
	return nil
}

func (p *Key) selfSign(issuer sign.PrivateKey, v Validity) error {
	if err := p.checkKey(issuer); err != nil {
		return err
	}
	sig, err := SignObject(issuer, v, p)
	if err == nil {
		p.self = sig
	}
	return err
}

// PacketTag implements pack.Packable interface.
func (*Key) PacketTag() pack.Tag { return PacketTagKey }

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p Key) EncodeMsgpack(enc *pack.Encoder) error {
	binds := make([]RawCertificate, 0, len(p.bindings))
	for _, bind := range p.bindings {
		binds = append(binds, *bind)
	}
	return enc.Encode(Model{
		Key:            NewKeyModel(p.Key()),
		Created:        p.created,
		Self:           p.self,
		Bindings:       binds,
		Certifications: p.certifications,
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *Key) DecodeMsgpack(dec *pack.Decoder) (err error) {
	m := new(Model)
	if err = dec.Decode(m); err != nil {
		return err
	}

	key, err := m.UnpackKey()
	if err != nil {
		return err
	}
	p.pk = key
	p.created = m.Created
	p.self = m.Self
	p.bindings = func(bindings []RawCertificate) map[CertID]*RawCertificate {
		m := make(map[CertID]*RawCertificate, len(bindings))
		for i := range bindings {
			m[bindings[i].ID] = &bindings[i]
		}
		return m
	}(m.Bindings)
	p.certifications = m.Certifications
	return nil
}
