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
func Generate(scheme sign.Scheme, expires int64) (*Key, sign.PrivateKey, error) {
	return Derive(scheme, crypto.Rand(scheme.SeedSize()), NewValidity(time.Now().Unix(), expires))
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

var _ pack.Packable = (*Key)(nil)
var _ pack.CustomEncoder = (*Key)(nil)
var _ pack.CustomDecoder = (*Key)(nil)

type Key struct {
	pk             sign.PublicKey
	certs          map[CertID]*RawCertificate
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
func (p *Key) CorrespondsTo(sk sign.PrivateKey) bool { return p.pk.CorrespondsTo(sk) }

// SelfSignature returns self-signature.
func (p *Key) SelfSignature() Signature { return p.self.Copy() }

// Validity returns identity validity.
func (p *Key) Validity() (int64, Validity) {
	return p.created, p.self.Validity
}

// Verify verifies the identity certification.
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

// Bindings returns identity bindings.
func (p *Key) Bindings() []RawBinding {
	binds := make([]RawBinding, 0, len(p.bindings))
	for _, bind := range p.bindings {
		binds = append(binds, bind.Copy())
	}
	return binds
}

// ErrBindingNotFound is returned if the binding is not found.
var ErrBindingNotFound = errors.New("binding not found")

func (p *Key) getBinding(id CertID) (*RawBinding, error) {
	bind, ok := p.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	return bind, nil
}

// GetBinding returns the binding.
func (p *Key) GetBinding(id CertID) (RawBinding, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return RawBinding{}, err
	}
	return bind.Copy(), nil
}

// GetBinding returns the binding with constrained type.
func GetBinding[T Bindable[T]](ident *Key, id CertID) (Binding[T], error) {
	var empty Binding[T]
	bind, err := ident.getBinding(id)
	if err != nil {
		return empty, err
	}
	return BindingAs[T](bind.Copy())
}

func signBinding[T Bindable[T]](id *Key, sk sign.PrivateKey, b *Binding[T], v Validity) error {
	if err := id.checkKey(sk); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	return b.Cert().Sign(sk, v)
}

// Bind binds the data to the identity.
func Bind[T Bindable[T]](id *Key, sk sign.PrivateKey, expires int64, data T) (Binding[T], error) {
	bind := NewBinding(data)
	err := signBinding(id, sk, &bind, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return bind, err
	}
	raw := bind.Raw()
	return bind, id.addBinding(&raw)
}

// Bind binds the data to the identity.
func (p *Key) Bind(sk sign.PrivateKey, expires int64, bind RawBinding) (RawBinding, error) {
	err := signBinding(p, sk, &bind, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return RawBinding{}, err
	}
	cpy := bind.Copy()
	return bind, p.addBinding(&cpy)
}

func (p *Key) addBinding(bind *RawBinding) error {
	if p.bindings == nil {
		p.bindings = make(map[CertID]*RawBinding)
	}
	if _, err := p.GetBinding(bind.ID); err == nil {
		return errors.New("duplicate binding")
	}
	p.bindings[bind.ID] = bind
	return nil
}

// Rebind rebinds the data to the identity with new expiration time.
// It does not change the binding ID.
func (p *Key) Rebind(id CertID, sk sign.PrivateKey, expires int64) (RawBinding, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return bind.Copy(), err
	}
	now := time.Now().Unix()
	if v := bind.Validity(); v.IsExpired(now) || v.IsRevoked(now) {
		return RawBinding{}, errors.New("binding is expired or revoked")
	}
	err = signBinding(p, sk, bind, NewValidity(now, expires))
	return bind.Copy(), err
}

// RevokeBinding revokes the binding.
func (p *Key) RevokeBinding(id CertID, sk sign.PrivateKey, reason string) (RawBinding, error) {
	b, err := p.getBinding(id)
	if err != nil {
		return RawBinding{}, err
	}
	err = signBinding(p, sk, b, b.Validity().Revoke(time.Now().Unix(), reason))
	return b.Copy(), err
}

// DeleteBinding deletes the expired or revoked binding.
func (p *Key) DeleteBinding(id CertID) (RawBinding, error) {
	b, err := p.getBinding(id)
	if err != nil {
		return RawBinding{}, err
	}
	now := time.Now().Unix()
	if v := b.Validity(); !v.IsExpired(now) && !v.IsRevoked(now) {
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

// Certify signs the identity.
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

// ChangeExpiry changes the expiration time of the identity.
func (p *Key) ChangeExpiry(sk sign.PrivateKey, expiry int64) error {
	return p.selfSign(sk, NewValidity(time.Now().Unix(), expiry))
}

// Revoke revokes the identity.
func (p *Key) Revoke(sk sign.PrivateKey, reason string) error {
	now := time.Now().Unix()
	if p.self.Validity.IsRevoked(now) {
		return errors.New("the key is already revoked")
	}
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
	now := time.Now().Unix()
	if v := p.self.Validity; v.IsExpired(now) || v.IsRevoked(now) {
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
func (*Key) PacketTag() pack.Tag { return PacketTagIdentity }

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p Key) EncodeMsgpack(enc *pack.Encoder) error {
	binds := make([]RawBinding, 0, len(p.bindings))
	for _, bind := range p.bindings {
		binds = append(binds, *bind)
	}
	return enc.Encode(Model{
		Key: KeyModel{
			Algorithm: p.Key().Scheme().Name(),
			Key:       p.Key().Pack(),
		},
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
	p.bindings = func(bindings []RawBinding) map[CertID]*RawBinding {
		m := make(map[CertID]*RawBinding, len(bindings))
		for i := range bindings {
			m[bindings[i].ID] = &bindings[i]
		}
		return m
	}(m.Bindings)
	p.certifications = m.Certifications
	return nil
}
