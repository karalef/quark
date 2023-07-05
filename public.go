package quark

import (
	"errors"
	"time"

	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

// ErrPublicKeysetSignature is returned if the public keyset signature is invalid.
type ErrPublicKeysetSignature struct {
	err          error
	verification bool
}

func (e ErrPublicKeysetSignature) Error() string {
	if e.verification {
		return "public keyset signature cannot be verified: " + e.err.Error()
	}
	return "public keyset signature: " + e.err.Error()
}

var _ Public = (*public)(nil)
var _ pack.CustomEncoder = (*public)(nil)
var _ pack.CustomDecoder = (*public)(nil)

// publicPart is used to create certification signatures.
type publicPart struct {
	publicKeyset `msgpack:",inline"`
	keysetInfo   `msgpack:",inline"`
}

type public struct {
	publicPart
	keysetSigs
}

func (p *public) pub() *public { return p }

// PacketTag implements pack.Packable interface.
func (*public) PacketTag() pack.Tag { return PacketTagPublicKeyset }

// ID returns the ID of the keyset.
func (p *public) ID() ID { return p.id }

// Fingerprint returns the fingerprint of the keyset.
func (p *public) Fingerprint() Fingerprint { return p.fp }

// Scheme returns the scheme of the keyset.
func (p *public) Scheme() Scheme { return p.publicPart.Scheme }

// Identity returns the identity of the keyset.
func (p *public) Identity() Identity { return p.publicPart.Identity }

// Validity returns the validity of the keyset.
func (p *public) Validity() Validity { return p.publicPart.Validity }

// SelfSignature returns the self-signature.
func (p *public) SelfSignature() CertificationSignature { return p.Self.Copy() }

// Signatures returns certification signatures.
func (p *public) Signatures() []CertificationSignature {
	sigs := make([]CertificationSignature, len(p.Sigs))
	for i, sig := range p.Sigs {
		sigs[i] = sig.Copy()
	}
	return sigs
}

// Cert returns the certification public key.
func (p *public) Cert() sign.PublicKey { return p.publicPart.cert }

// Sign returns the signature public key.
func (p *public) Sign() sign.PublicKey { return p.publicPart.sign }

// KEM returns the KEM public key.
func (p *public) KEM() kem.PublicKey { return p.publicPart.kem }

func (p *public) sign(issuer Private) error {
	time := time.Now().Unix()
	signer, err := signStream(issuer.Cert(), time)
	if err != nil {
		return err
	}
	err = pack.EncodeBinary(signer, p.publicPart)
	if err != nil {
		return err
	}
	sig := CertificationSignature{
		Issuer:    issuer.ID(),
		Time:      time,
		Signature: signer.Sign(),
	}
	if issuer.ID() == p.ID() {
		p.Self = sig
	} else {
		p.Sigs = append(p.Sigs, sig)
	}
	return nil
}

func (p *public) verify() error {
	verifier, err := verifyStream(p.publicPart.sign, p.Self.Time)
	if err != nil {
		return ErrPublicKeysetSignature{
			err:          err,
			verification: true,
		}
	}
	err = pack.EncodeBinary(verifier, p.publicPart)
	if err != nil {
		return ErrPublicKeysetSignature{
			err:          err,
			verification: true,
		}
	}
	ok, err := verifier.Verify(p.Self.Signature)
	if err != nil {
		return ErrPublicKeysetSignature{
			err:          err,
			verification: true,
		}
	}
	if !ok {
		return ErrPublicKeysetSignature{
			err:          errors.New("wrong signature"),
			verification: true,
		}
	}
	return nil
}

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p public) EncodeMsgpack(enc *pack.Encoder) error {
	err := enc.Encode(p.publicPart)
	if err != nil {
		return err
	}
	return enc.Encode(p.keysetSigs)
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *public) DecodeMsgpack(dec *pack.Decoder) (err error) {
	if err = dec.Decode(&p.publicPart); err != nil {
		return err
	}
	if err = dec.Decode(&p.keysetSigs); err != nil {
		return err
	}

	if !p.Identity().IsValid() {
		return ErrInvalidIdentity
	}

	return p.verify()
}

// newPublic is used to create a public keyset from the newly generated keys.
func newPublic(identity Identity, expires int64, ks publicKeyset) (*public, error) {
	if !identity.IsValid() {
		return nil, ErrInvalidIdentity
	}
	if expires < 0 {
		panic("invalid expiration time")
	}

	return &public{
		publicPart: publicPart{
			publicKeyset: ks,
			keysetInfo: keysetInfo{
				Identity: identity,
				Validity: Validity{
					Created: time.Now().Unix(),
					Expires: expires,
				},
			},
		},
	}, nil
}
