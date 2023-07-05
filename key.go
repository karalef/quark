package quark

import (
	"errors"
	"time"

	"github.com/karalef/quark/crypto/kem"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
	"golang.org/x/crypto/sha3"
)

type keysetInfo struct {
	Identity Identity `msgpack:"identity"`
	Validity Validity `msgpack:"validity"`
}

func (i *keysetInfo) changeIdentity(id Identity) error {
	if !id.IsValid() {
		return ErrInvalidIdentity
	}
	i.Identity = id
	return nil
}

func (i *keysetInfo) changeExpiry(expiry int64) error {
	if expiry < time.Now().Unix() {
		return errors.New("expiration time cannot be in the past")
	}
	i.Validity.Expires = expiry
	return nil
}

func (i *keysetInfo) revoke(reason string) error {
	if i.Validity.Revoked != 0 {
		return errors.New("the keyset is already revoked")
	}
	i.Validity.Revoked = time.Now().Unix()
	i.Validity.Reason = reason
	return nil
}

type keysetSigs struct {
	Self CertificationSignature   `msgpack:"self"`
	Sigs []CertificationSignature `msgpack:"sigs"`
}

// fpPart contains immutable parts of the keyset
// so it is used to calculate the fingerprint and id.
type fpPart struct {
	Scheme Scheme `msgpack:"scheme"`
	Cert   []byte `msgpack:"cert"`
	Sign   []byte `msgpack:"sign"`
	KEM    []byte `msgpack:"kem"`
}

func (f fpPart) fp() (fp Fingerprint) {
	if f.Cert == nil {
		panic("fpPart must be non-empty")
	}
	sha3 := sha3.New256()
	err := pack.EncodeBinary(sha3, f)
	if err != nil {
		panic(err)
	}
	sha3.Sum(fp[:0])
	return
}

func newPrivateKeyset(scheme Scheme, certSeed, signSeed, kemSeed []byte) (ks privateKeyset, err error) {
	ks.cert, ks.public.cert, err = scheme.Cert.DeriveKey(certSeed)
	if err != nil {
		return
	}
	ks.sign, ks.public.sign, err = scheme.Sign.DeriveKey(signSeed)
	if err != nil {
		return
	}
	ks.kem, ks.public.kem, err = scheme.KEM.DeriveKey(kemSeed)
	if err != nil {
		return
	}
	ks.fpPart = fpPart{
		Scheme: scheme,
		Cert:   certSeed,
		Sign:   signSeed,
		KEM:    kemSeed,
	}
	ks.public = newPublicKeyset(scheme, ks.public.cert, ks.public.sign, ks.public.kem)
	return
}

type privateKeyset struct {
	public publicKeyset
	cert   sign.PrivateKey
	sign   sign.PrivateKey
	kem    kem.PrivateKey

	fpPart `msgpack:",inline"`
}

func (p *privateKeyset) DecodeMsgpack(dec *pack.Decoder) error {
	err := dec.Decode(&p.fpPart)
	if err != nil {
		return err
	}

	p.cert, p.public.cert, err = p.Scheme.Cert.DeriveKey(p.Cert)
	if err != nil {
		return err
	}
	p.sign, p.public.sign, err = p.Scheme.Sign.DeriveKey(p.Sign)
	if err != nil {
		return err
	}
	p.kem, p.public.kem, err = p.Scheme.KEM.DeriveKey(p.KEM)
	if err != nil {
		return err
	}
	p.public = newPublicKeyset(p.Scheme, p.public.cert, p.public.sign, p.public.kem)
	return err
}

func newPublicKeyset(scheme Scheme, certKey, signKey sign.PublicKey, kemKey kem.PublicKey) publicKeyset {
	raw := fpPart{
		Scheme: scheme,
		Cert:   certKey.Bytes(),
		Sign:   signKey.Bytes(),
		KEM:    kemKey.Bytes(),
	}
	fp := raw.fp()
	return publicKeyset{
		id:     fp.ID(),
		fp:     fp,
		cert:   certKey,
		sign:   signKey,
		kem:    kemKey,
		fpPart: raw,
	}
}

type publicKeyset struct {
	id   ID
	fp   Fingerprint
	cert sign.PublicKey
	sign sign.PublicKey
	kem  kem.PublicKey

	fpPart `msgpack:",inline"`
}

func (p *publicKeyset) DecodeMsgpack(dec *pack.Decoder) error {
	err := dec.Decode(&p.fpPart)
	if err != nil {
		return err
	}

	p.fp = p.fpPart.fp()
	p.id = p.fp.ID()
	p.cert, err = p.Scheme.Cert.UnpackPublic(p.Cert)
	if err != nil {
		return err
	}
	p.sign, err = p.Scheme.Sign.UnpackPublic(p.Sign)
	if err != nil {
		return err
	}
	p.kem, err = p.Scheme.KEM.UnpackPublic(p.KEM)
	return err
}
