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
func Generate(scheme sign.Scheme, expires int64) (*Identity, PrivateKey, error) {
	seed := crypto.Rand(scheme.SeedSize())
	return Derive(scheme, seed, expires)
}

// Derive deterministically creates a new key and an identity.
func Derive(scheme sign.Scheme, seed []byte, expires int64) (*Identity, PrivateKey, error) {
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

var _ pack.Packable = (*Identity)(nil)
var _ pack.CustomEncoder = (*Identity)(nil)
var _ pack.CustomDecoder = (*Identity)(nil)

type Identity struct {
	pk             PublicKey
	bindings       map[BindID]*Binding
	certifications []Signature
	self           Signature
	created        int64
}

// ID returns key ID.
func (p *Identity) ID() ID { return p.pk.ID() }

// Fingerprint returns key fingerprint.
func (p *Identity) Fingerprint() Fingerprint { return p.pk.Fingerprint() }

// Key returns public key.
func (p *Identity) Key() PublicKey { return p.pk }

// CorrespondsTo returns true if key corresponds to given private key.
func (p *Identity) CorrespondsTo(sk PrivateKey) bool { return p.pk.CorrespondsTo(sk) }

// SelfSignature returns self-signature.
func (p *Identity) SelfSignature() Signature { return p.self.Copy() }

// Validity returns identity validity.
func (p *Identity) Validity() (int64, Validity) {
	return p.created, p.self.Validity
}

// Verify verifies the identity certification.
// It also can verify the self-signature.
func (p *Identity) Verify(key PublicKey, sig Signature) error {
	if key.Fingerprint() != sig.Issuer {
		return errors.New("wrong issuer")
	}
	verifier := VerifyStream(key)
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

// ListBindings returns the short version of identity bindings.
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

// GetBinding returns the binding.
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

// Bind binds the data to the identity.
func (p *Identity) Bind(sk PrivateKey, b BindingData, expires int64) (Binding, error) {
	if len(b.Data) == 0 {
		return Binding{}, errors.New("empty data")
	}
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

// Rebind rebinds the data to the identity with new expiration time.
// It does not change the binding ID.
func (p *Identity) Rebind(id BindID, sk PrivateKey, expires int64) (Binding, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}
	now := time.Now().Unix()
	if v := bind.Signature.Validity; v.IsExpired(now) || v.IsRevoked(now) {
		return Binding{}, errors.New("binding is expired or revoked")
	}
	err = p.signBinding(sk, bind, NewValidity(now, expires))
	return bind.Copy(), err
}

// ChnageBinding changes the data and metadata of the binding.
// It changes the binding ID.
//
// # If data is
//
// - nil: data will be unchanged.
//
// - empty: binding will be unbound if it is expired or revoked else the error will be returned.
//
// # If metadata is
//
// - nil: metadata will be unchanged.
//
// - empty: metadata will be removed.
func (p *Identity) ChangeBinding(id BindID, sk PrivateKey, newData []byte, md Metadata) (Binding, error) {
	bind, err := p.getBinding(id)
	if err != nil {
		return Binding{}, err
	}

	now := time.Now().Unix()
	if newData != nil && len(newData) > 0 { // special case: delete binding
		v := bind.Signature.Validity
		if v.IsExpired(now) || v.IsRevoked(now) {
			delete(p.bindings, bind.ID)
			return Binding{}, nil
		}
		return Binding{}, errors.New("binding is not expired or revoked")
	}

	if !p.CorrespondsTo(sk) {
		return Binding{}, ErrKeyNotCorrespond
	}

	newBind := bind.Copy()
	if newData != nil {
		newBind.Data = newData
	}
	if md != nil {
		if len(md) == 0 {
			newBind.Metadata = nil
		} else {
			newBind.Metadata = md
		}
	}
	err = p.signBinding(sk, &newBind, newBind.Signature.Validity)
	if err != nil {
		return bind.Copy(), err
	}
	*bind = newBind
	return newBind.Copy(), err
}

// RevokeBinding revokes the binding.
func (p *Identity) RevokeBinding(id BindID, sk PrivateKey, reason string) (Binding, error) {
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

// Certify signs the identity.
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

// ChangeExpiry changes the expiration time of the identity.
func (p *Identity) ChangeExpiry(sk PrivateKey, expiry int64) error {
	return p.selfSign(sk, NewValidity(time.Now().Unix(), expiry))
}

// Revoke revokes the identity.
func (p *Identity) Revoke(sk PrivateKey, reason string) error {
	now := time.Now().Unix()
	if p.self.Validity.IsRevoked(now) {
		return errors.New("the key is already revoked")
	}
	return p.selfSign(sk, p.self.Validity.Revoke(now, reason))
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
	if !p.CorrespondsTo(issuer) {
		return ErrKeyNotCorrespond
	}
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
		Key: KeyModel{
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
