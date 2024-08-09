package quark

import (
	"errors"
	"io"
	"time"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// Generate generates a new key using crypto/rand and creates an identity.
func Generate(scheme sign.Scheme, expires int64) (Identity, PrivateKey, error) {
	seed := crypto.Rand(scheme.SeedSize())
	return Derive(scheme, expires, seed)
}

// Derive deterministically creates a new key and an identity.
func Derive(scheme sign.Scheme, expires int64, seed []byte) (Identity, PrivateKey, error) {
	pk, sk, err := DeriveKey(scheme, seed)
	if err != nil {
		return nil, nil, err
	}

	id := &identity{
		PublicKey: pk,
		created:   time.Now().Unix(),
	}

	err = id.selfSign(sk, NewValidity(id.created, expires))
	if err != nil {
		return nil, nil, err
	}

	return id, sk, nil
}

// Identity represents an identity.
type Identity interface {
	pack.Packable

	KeyID
	Key() PublicKey

	// Validity returns the creation time and self signature validity.
	Validity() (int64, Validity)
	// ChangeExpiry changes the expiration time.
	ChangeExpiry(expires int64, sk PrivateKey) error
	// Revoke revokes the identity.
	Revoke(reason string, sk PrivateKey) error

	// Bindings returns identity bindings.
	Bindings() []Binding
	// ListBindings returns identity bindings.
	ListBindings() []ShortBinding
	// GetBinding returns an identity binding by ID.
	GetBinding(BindID) (Binding, error)
	// Bind binds any data to the identity.
	Bind(sk PrivateKey, b BindingData, expires int64) (Binding, error)
	// Rebind changes the binding and updates the signature.
	Rebind(id BindID, sk PrivateKey, group string, expires int64) (Binding, error)
	// Unbind revokes a binding and returns the revoked binding.
	Unbind(id BindID, sk PrivateKey, reason string) (Binding, error)

	// SelfSignature returns identity self signature.
	SelfSignature() Signature
	// Certifications returns certifications by other identities.
	Certifications() []Signature
	// Certify signs the identity.
	Certify(with PrivateKey, expires int64) error
	// Verify verifies the identity signature.
	// It also accepts the self signature.
	Verify(Identity, Signature) error
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

var _ Identity = (*identity)(nil)
var _ pack.CustomEncoder = (*identity)(nil)
var _ pack.CustomDecoder = (*identity)(nil)

type identity struct {
	PublicKey
	sk             *privateKey
	bindings       map[BindID]*Binding
	certifications []Signature
	self           Signature
	created        int64
}

func (p *identity) Key() PublicKey           { return p.PublicKey }
func (p *identity) SelfSignature() Signature { return p.self.Copy() }

func (p *identity) Validity() (int64, Validity) {
	return p.created, p.self.Validity
}

func (p *identity) Verify(id Identity, sig Signature) error {
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
func (p *identity) Bindings() []Binding {
	binds := make([]Binding, len(p.bindings))
	i := 0
	for _, bind := range p.bindings {
		binds[i] = bind.Copy()
		i++
	}
	return binds
}

func (p *identity) ListBindings() []ShortBinding {
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

func (p *identity) getBinding(id BindID) (*Binding, error) {
	bind, ok := p.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	return bind, nil
}

func (p *identity) GetBinding(id BindID) (Binding, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}
	return bind.Copy(), nil
}

func (p *identity) signBinding(sk PrivateKey, b *Binding, v Validity) error {
	if !p.CorrespondsTo(sk) {
		return ErrKeyNotCorrespond
	}
	if !b.CheckIntegrity(p.PublicKey) {
		return errors.New("invalid binding")
	}
	return b.sign(sk, v)
}

func (p *identity) Bind(sk PrivateKey, b BindingData, expires int64) (Binding, error) {
	if !p.CorrespondsTo(sk) {
		return Binding{}, ErrKeyNotCorrespond
	}
	bind := NewBinding(p.PublicKey, b)
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

func (p *identity) Rebind(id BindID, sk PrivateKey, group string, expires int64) (Binding, error) {
	if !p.CorrespondsTo(sk) {
		return Binding{}, ErrKeyNotCorrespond
	}
	bind, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}
	if group == "" { // changes the signature only, so no copy is needed
		err = p.signBinding(sk, bind, NewValidity(time.Now().Unix(), expires))
		return bind.Copy(), err
	}

	cpy := bind.Copy()
	cpy.Group = group
	err = p.signBinding(sk, &cpy, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return bind.Copy(), err
	}
	*bind = cpy
	return cpy, err
}

func (p *identity) Unbind(id BindID, sk PrivateKey, reason string) (Binding, error) {
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
func (p *identity) Certifications() []Signature {
	certs := make([]Signature, len(p.certifications))
	for i, cert := range p.certifications {
		certs[i] = cert.Copy()
	}
	return certs
}

func (p *identity) Certify(with PrivateKey, expires int64) error {
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

func (p *identity) ChangeExpiry(expiry int64, sk PrivateKey) error {
	if !p.CorrespondsTo(sk) {
		return ErrKeyNotCorrespond
	}
	return p.selfSign(sk, NewValidity(time.Now().Unix(), expiry))
}

func (p *identity) Revoke(reason string, sk PrivateKey) error {
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

func (p *identity) signEncode(w io.Writer) error {
	key := p.Raw()
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

func (p *identity) selfSign(issuer PrivateKey, v Validity) error {
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
func (*identity) PacketTag() pack.Tag { return PacketTagIdentity }

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p identity) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.Encode(idModel{
		Public: &KeyModel{
			Algorithm: p.Raw().Scheme().Name(),
			Key:       p.Raw().Pack(),
		},
		Created:        p.created,
		Self:           p.self,
		Bindings:       p.Bindings(),
		Certifications: p.certifications,
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *identity) DecodeMsgpack(dec *pack.Decoder) (err error) {
	m := new(idModel)
	if err = dec.Decode(m); err != nil {
		return err
	}

	if m.Public == nil {
		return UnpackError("object does not contain public key")
	}
	scheme := sign.ByName(m.Public.Algorithm)
	if scheme == nil {
		return UnpackError("scheme not found: " + m.Public.Algorithm)
	}
	if len(m.Public.Key) != scheme.PublicKeySize() {
		return UnpackError("invalid public key size")
	}
	key, err := scheme.UnpackPublic(m.Public.Key)
	if err != nil {
		return UnpackError("invalid public key: " + err.Error())
	}
	p.PublicKey = &publicKey{PublicKey: key}
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
