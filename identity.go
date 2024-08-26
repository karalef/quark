package quark

import (
	"errors"
	"io"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/keys"
	"github.com/karalef/quark/pack"
)

// Generate generates a new key using crypto/rand and creates an identity.
func Generate(scheme sign.Scheme, expires int64) (*Identity, PrivateKey, error) {
	seed := crypto.Rand(scheme.SeedSize())
	return Derive(scheme, expires, seed)
}

// Derive deterministically creates a new key and an identity.
func Derive(scheme sign.Scheme, expires int64, seed []byte) (*Identity, PrivateKey, error) {
	sk, pk, err := scheme.DeriveKey(seed)
	if err != nil {
		return nil, nil, err
	}

	id := &Identity{
		pk:      pk,
		created: time.Now().Unix(),
	}

	err = id.selfSign(sk, NewValidity(id.created, expires))
	if err != nil {
		return nil, nil, err
	}

	return id, sk, nil
}

// ErrSignature is returned if the public key signature is invalid.
type ErrSignature struct {
	err          error
	verification bool
}

func (e ErrSignature) Error() string {
	if e.verification {
		return "public key signature cannot be verified: " + e.err.Error()
	}
	return "public key signature: " + e.err.Error()
}

var _ pack.Packable = (*Identity)(nil)
var _ pack.CustomEncoder = (*Identity)(nil)
var _ pack.CustomDecoder = (*Identity)(nil)

type Identity struct {
	pk             PublicKey
	esk            *EncryptedKey
	bindings       map[BindID]*Binding
	certifications []Signature
	self           Signature
	created        int64
}

func (p *Identity) ID() ID                           { return p.pk.ID() }
func (p *Identity) Fingerprint() Fingerprint         { return p.pk.Fingerprint() }
func (p *Identity) Key() PublicKey                   { return p.pk }
func (p *Identity) CorrespondsTo(sk PrivateKey) bool { return p.pk.CorrespondsTo(sk) }
func (p *Identity) SelfSignature() Signature         { return p.self.Copy() }
func (p *Identity) WithPrivateKey(sk *EncryptedKey)  { p.esk = sk }

// PrivateKey returns the private key if it is available.
// This function returns the available key only one time.
func (p *Identity) PrivateKey() *EncryptedKey {
	esk := p.esk
	p.esk = nil
	return esk
}

func (p *Identity) Validity() (int64, Validity) {
	return p.created, p.self.Validity
}

func (p *Identity) Verify(id *Identity, sig Signature) error {
	if id.Fingerprint() != sig.Issuer {
		return errors.New("wrong issuer")
	}
	verifier := VerifyStream(id.Key())
	err := p.signEncode(verifier)
	if err != nil {
		return err
	}
	ok, err := verifier.Verify(sig)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("wrong signature")
	}
	return nil
}

// Bindings returns identity bindings.
func (p *Identity) Bindings() []Binding {
	binds := make([]Binding, len(p.bindings))
	i := 0
	for _, bind := range p.bindings {
		binds[i] = bind.Copy()
		i++
	}
	return binds
}

func (p *Identity) ListBindings() []ShortBinding {
	binds := make([]ShortBinding, len(p.bindings))
	i := 0
	for _, bind := range p.bindings {
		binds[i] = bind.Short()
		i++
	}
	return binds
}

// ErrBindingNotFound is returned if the binding is not found.
var ErrBindingNotFound = errors.New("binding not found")

func (p *Identity) getBinding(id BindID) (*Binding, error) {
	bind, ok := p.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	return bind, nil
}

func (p *Identity) GetBinding(id BindID) (Binding, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}
	return bind.Copy(), nil
}

func (p *Identity) signBinding(sk PrivateKey, b *Binding, v Validity) error {
	if !p.CorrespondsTo(sk) {
		return ErrKeyNotCorrespond
	}
	if !b.CheckIntegrity(p.pk) {
		return errors.New("invalid binding")
	}
	return b.sign(sk, v)
}

func (p *Identity) Bind(sk PrivateKey, b BindingData, expires int64) (Binding, error) {
	if !p.CorrespondsTo(sk) {
		return Binding{}, ErrKeyNotCorrespond
	}
	bind := NewBinding(p.pk, b)
	if p.bindings == nil {
		p.bindings = make(map[BindID]*Binding)
	}
	if b, ok := p.bindings[bind.ID]; ok {
		return b.Copy(), errors.New("duplicate binding")
	}
	err := p.signBinding(sk, &bind, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return Binding{}, err
	}
	p.bindings[bind.ID] = &bind
	return bind.Copy(), nil
}

func (p *Identity) Rebind(id BindID, sk PrivateKey, expires int64) (Binding, error) {
	if !p.CorrespondsTo(sk) {
		return Binding{}, ErrKeyNotCorrespond
	}
	bind, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}
	err = p.signBinding(sk, bind, NewValidity(time.Now().Unix(), expires))
	return bind.Copy(), err
}

func (p *Identity) ChangeBinding(id BindID, sk PrivateKey, md Metadata) (Binding, error) {
	if !p.CorrespondsTo(sk) {
		return Binding{}, ErrKeyNotCorrespond
	}
	bind, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}

	cpy := bind.Copy()
	cpy.Metadata = md
	err = p.signBinding(sk, &cpy, cpy.Signature.Validity)
	if err != nil {
		return bind.Copy(), err
	}
	*bind = cpy
	return cpy, err
}

func (p *Identity) Unbind(id BindID, sk PrivateKey, reason string) (Binding, error) {
	if !p.CorrespondsTo(sk) {
		return Binding{}, ErrKeyNotCorrespond
	}
	b, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}
	err = p.signBinding(sk, b, b.Signature.Validity.Revoke(time.Now().Unix(), reason))
	return b.Copy(), err
}

// Certifications returns certification signatures.
func (p *Identity) Certifications() []Signature {
	certs := make([]Signature, len(p.certifications))
	for i, cert := range p.certifications {
		certs[i] = cert.Copy()
	}
	return certs
}

func (p *Identity) Certify(with PrivateKey, expires int64) error {
	if p.CorrespondsTo(with) {
		return errors.New("the key cannot certify itself")
	}
	signer := SignStream(with)
	err := p.signEncode(signer)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return err
	}
	p.certifications = append(p.certifications, sig)
	return nil
}

func (p *Identity) ChangeExpiry(expiry int64, sk PrivateKey) error {
	if !p.CorrespondsTo(sk) {
		return ErrKeyNotCorrespond
	}
	return p.selfSign(sk, NewValidity(time.Now().Unix(), expiry))
}

func (p *Identity) Revoke(reason string, sk PrivateKey) error {
	if !p.CorrespondsTo(sk) {
		return ErrKeyNotCorrespond
	}
	if p.self.Validity.Revoked != 0 {
		return errors.New("the key is already revoked")
	}
	now := time.Now().Unix()
	return p.selfSign(sk, Validity{
		Created: now,
		Expires: 0,
		Revoked: now,
		Reason:  reason,
	})
}

func (p *Identity) signEncode(w io.Writer) error {
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

func (p *Identity) selfSign(issuer PrivateKey, v Validity) error {
	signer := SignStream(issuer)
	err := p.signEncode(signer)
	if err != nil {
		return err
	}
	sig, err := signer.Sign(v)
	if err == nil {
		p.self = sig
	}
	return err
}

// PacketTag implements pack.Packable interface.
func (*Identity) PacketTag() pack.Tag { return PacketTagIdentity }

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p Identity) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(idModel{
		Public: &keys.Model{
			Algorithm: p.Key().Scheme().Name(),
			Key:       p.Key().Pack(),
		},
		Created:        p.created,
		Self:           p.self,
		Bindings:       p.Bindings(),
		Certifications: p.certifications,
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *Identity) DecodeMsgpack(dec *pack.Decoder) (err error) {
	m := new(idModel)
	if err = dec.Decode(m); err != nil {
		return err
	}

	key, err := m.UnpackKey()
	if err != nil {
		return err
	}
	p.pk = key
	p.esk = m.Private
	p.created = m.Created
	p.self = m.Self
	p.bindings = func(bindings []Binding) map[BindID]*Binding {
		m := make(map[BindID]*Binding, len(bindings))
		for i := range bindings {
			c := bindings[i].Copy()
			m[bindings[i].ID] = &c
		}
		return m
	}(m.Bindings)
	p.certifications = m.Certifications
	return nil
}
