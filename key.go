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
func (k *Key) ID() crypto.ID { return k.pk.ID() }

// Fingerprint returns key fingerprint.
func (k *Key) Fingerprint() crypto.Fingerprint { return k.pk.Fingerprint() }

// Key returns public key.
func (k *Key) Key() sign.PublicKey { return k.pk }

// CorrespondsTo returns true if key corresponds to given private key.
func (k *Key) CorrespondsTo(sk sign.PrivateKey) bool { return sign.CorrespondsTo(k.Key(), sk) }

// SelfSignature returns self-signature.
func (k *Key) SelfSignature() Signature { return k.self.Copy() }

// Validity returns key validity.
func (k *Key) Validity() (int64, Validity) {
	return k.created, k.self.Validity
}

// Verify verifies the key certification.
// It also can verify the self-signature.
func (k *Key) Verify(key sign.PublicKey, sig Signature) error {
	if key.Fingerprint() != sig.Issuer {
		return errors.New("wrong issuer")
	}
	ok, err := sig.VerifyObject(key, k)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("wrong signature")
	}
	return nil
}

// Bindings returns key bindings.
func (k *Key) Bindings() []RawCertificate {
	binds := make([]RawCertificate, 0, len(k.bindings))
	for _, bind := range k.bindings {
		binds = append(binds, bind.Copy())
	}
	return binds
}

// BindingsCount returns key bindings count.
func (k *Key) BindingsCount() uint { return uint(len(k.bindings)) }

// VisitAllBindings visits all bindings.
func (k *Key) VisitAllBindings(f func(RawCertificate) (stop bool)) {
	for _, bind := range k.bindings {
		if f(bind.Copy()) {
			break
		}
	}
}

// VisitAllBindingsUnsafe visits all bindings without making a copy.
// It is significally faster than VisitAllBindings and uses no extra memory,
// but can breaks the key if the binding will be modified.
func (k *Key) VisitAllBindingsUnsafe(f func(*RawCertificate) (stop bool)) {
	for _, bind := range k.bindings {
		if f(bind) {
			break
		}
	}
}

// ErrBindingNotFound is returned if the binding is not found.
var ErrBindingNotFound = errors.New("binding not found")

func (k *Key) getBinding(id CertID) (*RawCertificate, error) {
	bind, ok := k.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	return bind, nil
}

// GetBinding returns the binding.
func (k *Key) GetBinding(id CertID) (RawCertificate, error) {
	bind, err := k.getBinding(id)
	if err != nil {
		return RawCertificate{}, err
	}
	return bind.Copy(), nil
}

// GetBinding returns the binding with constrained type.
func GetBinding[T Certifyable[T]](k *Key, id CertID) (Certificate[T], error) {
	bind, err := k.getBinding(id)
	if err != nil {
		return Certificate[T]{}, err
	}
	return CertificateAs[T](*bind)
}

func signBinding[T Certifyable[T]](k *Key, sk sign.PrivateKey, b *Certificate[T], v Validity) error {
	if err := k.checkKey(sk); err != nil {
		return err
	}
	if err := b.Validate(); err != nil {
		return err
	}
	return b.Sign(sk, v)
}

// Bind binds the data to the key.
func Bind[T Certifyable[T]](k *Key, sk sign.PrivateKey, expires int64, data T) (CertID, error) {
	bind := NewCertificate(data).Raw()
	err := signBinding(k, sk, &bind, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return CertID{}, err
	}
	return bind.ID, k.addBinding(&bind)
}

// Bind binds the data to the key.
func (k *Key) Bind(sk sign.PrivateKey, expires int64, bind RawCertificate) error {
	err := signBinding(k, sk, &bind, NewValidity(time.Now().Unix(), expires))
	if err != nil {
		return err
	}
	cpy := bind.Copy()
	return k.addBinding(&cpy)
}

func (k *Key) addBinding(bind *RawCertificate) error {
	if k.bindings == nil {
		k.bindings = make(map[CertID]*RawCertificate)
	}
	if _, err := k.GetBinding(bind.ID); err == nil {
		return errors.New("duplicate binding")
	}
	k.bindings[bind.ID] = bind
	return nil
}

// Rebind rebinds the data to the key with new expiration time.
// It does not change the binding ID.
func (k *Key) Rebind(id CertID, sk sign.PrivateKey, expires int64) error {
	bind, err := k.getBinding(id)
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if v := bind.Validity(); !v.IsValid(now) {
		return errors.New("binding is expired or revoked")
	}
	return signBinding(k, sk, bind, NewValidity(now, expires))
}

// RevokeBinding revokes the binding.
func (k *Key) RevokeBinding(id CertID, sk sign.PrivateKey, reason string) error {
	b, err := k.getBinding(id)
	if err != nil {
		return err
	}
	v := b.Validity()
	if v.IsRevoked() {
		return errors.New("binding is already revoked")
	}
	return signBinding(k, sk, b, v.Revoke(time.Now().Unix(), reason))
}

// DeleteBinding deletes the expired or revoked binding.
func (k *Key) DeleteBinding(id CertID) (*RawCertificate, error) {
	b, err := k.getBinding(id)
	if err != nil {
		return nil, err
	}
	if v := b.Validity(); v.IsValid(time.Now().Unix()) {
		return nil, errors.New("binding is not expired or revoked")
	}
	delete(k.bindings, id)
	return b, nil
}

// Certifications returns certification signatures.
func (k *Key) Certifications() []Signature {
	certs := make([]Signature, len(k.certifications))
	for i, cert := range k.certifications {
		certs[i] = cert.Copy()
	}
	return certs
}

// Certify signs the key.
func (k *Key) Certify(with sign.PrivateKey, expires int64) error {
	if k.CorrespondsTo(with) {
		return errors.New("the key cannot certify itself")
	}
	sig, err := SignObject(with, NewValidity(time.Now().Unix(), expires), k)
	if err != nil {
		return err
	}
	k.certifications = append(k.certifications, sig)
	return nil
}

// ChangeExpiry changes the expiration time of the key.
func (k *Key) ChangeExpiry(sk sign.PrivateKey, expiry int64) error {
	return k.selfSign(sk, NewValidity(time.Now().Unix(), expiry))
}

// Revoke revokes the key.
func (k *Key) Revoke(sk sign.PrivateKey, reason string) error {
	if k.self.Validity.IsRevoked() {
		return errors.New("the key is already revoked")
	}
	now := time.Now().Unix()
	return k.selfSign(sk, k.self.Validity.Revoke(now, reason))
}

// SignEncode implements Signable.
func (k *Key) SignEncode(w io.Writer) error {
	key := k.Key()
	_, err := w.Write([]byte(key.Scheme().Name()))
	if err != nil {
		return err
	}
	_, err = w.Write(key.Pack())
	if err != nil {
		return err
	}
	_, err = w.Write(MarshalTime(k.created))
	return err
}

// ErrExpiredOrRevoked is returned if the key is expired or revoked.
var ErrExpiredOrRevoked = errors.New("key is expired or revoked")

func (k *Key) checkKey(sk sign.PrivateKey) error {
	if v := k.self.Validity; !v.IsValid(time.Now().Unix()) {
		return ErrExpiredOrRevoked
	}
	if !k.CorrespondsTo(sk) {
		return crypto.ErrKeyNotCorrespond
	}
	return nil
}

func (k *Key) selfSign(issuer sign.PrivateKey, v Validity) error {
	if err := k.checkKey(issuer); err != nil {
		return err
	}
	sig, err := SignObject(issuer, v, k)
	if err == nil {
		k.self = sig
	}
	return err
}

// PacketTag implements pack.Packable interface.
func (*Key) PacketTag() pack.Tag { return PacketTagKey }

// EncodeMsgpack implements pack.CustomEncoder interface.
func (k Key) EncodeMsgpack(enc *pack.Encoder) error {
	binds := make([]RawCertificate, 0, len(k.bindings))
	for _, bind := range k.bindings {
		binds = append(binds, *bind)
	}
	return enc.Encode(Model{
		Key:            NewKeyModel(k.Key()),
		Created:        k.created,
		Self:           k.self,
		Bindings:       binds,
		Certifications: k.certifications,
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (k *Key) DecodeMsgpack(dec *pack.Decoder) (err error) {
	m := new(Model)
	if err = dec.Decode(m); err != nil {
		return err
	}

	key, err := sign.UnpackPublic(m.Key.Algorithm, m.Key.Key)
	if err != nil {
		return err
	}
	k.pk = key
	k.created = m.Created
	k.self = m.Self
	k.bindings = func(bindings []RawCertificate) map[CertID]*RawCertificate {
		m := make(map[CertID]*RawCertificate, len(bindings))
		for i := range bindings {
			m[bindings[i].ID] = &bindings[i]
		}
		return m
	}(m.Bindings)
	k.certifications = m.Certifications
	return nil
}

// KeyModel returns the key model.
func NewKeyModel(key crypto.RawKey) KeyModel {
	return KeyModel{
		Algorithm: key.Scheme().Name(),
		Key:       key.Pack(),
	}
}

// KeyModel contains packed immutable parts of the key.
type KeyModel struct {
	Algorithm string `msgpack:"algorithm"`
	Key       []byte `msgpack:"key"`
}

// Model contains packed Key.
type Model struct {
	Key            KeyModel         `msgpack:"key"`
	Bindings       []RawCertificate `msgpack:"bindings,omitempty"`
	Certifications []Signature      `msgpack:"certifications,omitempty"`
	Self           Signature        `msgpack:"selfSignature"`
	Created        int64            `msgpack:"created,omitempty"`
}
