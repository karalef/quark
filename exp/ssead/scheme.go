package ssead

import (
	"encoding/binary"
	"io"

	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/scheme"
)

// New creates new SSEAD scheme. It does not register the scheme.
func New(name string, ciph cipher.Scheme, sig sign.Scheme) Scheme {
	return &sseadScheme{
		String: scheme.String(name),
		ciph:   ciph,
		sign:   sig,
	}
}

var _ Scheme = sseadScheme{}

type sseadScheme struct {
	scheme.String
	ciph cipher.Scheme
	sign sign.Scheme
}

func (s sseadScheme) KeySize() int       { return s.ciph.KeySize() }
func (s sseadScheme) IVSize() int        { return s.ciph.IVSize() }
func (s sseadScheme) SignatureSize() int { return s.sign.Size() }

func (s sseadScheme) Encrypt(sk sign.PrivateKey, key, iv, ad []byte) Encrypter {
	s.validate(sk.Scheme())
	return &encrypter{newCrypter(s.ciph, sk.Sign(), key, iv, ad)}
}

func (s sseadScheme) Decrypt(pk sign.PublicKey, key, iv, ad []byte) Decrypter {
	s.validate(pk.Scheme())
	return &decrypter{newCrypter(s.ciph, pk.Verify(), key, iv, ad)}
}

func (s sseadScheme) validate(sch sign.Scheme) {
	if !scheme.IsEqual(s.sign, sch) {
		panic("crypto/ssead: the key does not match the signature scheme")
	}
}

//nolint:errcheck
func newCrypter[W io.Writer](ciph cipher.Scheme, sign W, key, iv, ad []byte) crypter[W] {
	sign.Write(key)
	sign.Write(iv)
	sign.Write(ad)
	return crypter[W]{
		ciph:  ciph.New(key, iv),
		sign:  sign,
		adlen: uint64(len(ad)),
	}
}

type crypter[W io.Writer] struct {
	ciph  cipher.Cipher
	sign  W
	adlen uint64
	count uint64
}

//nolint:errcheck
func (c *crypter[_]) write(ct []byte) {
	c.sign.Write(ct)
	c.count += uint64(len(ct))
}

//nolint:errcheck
func (c *crypter[_]) finalize() {
	var lengths [16]byte
	binary.BigEndian.PutUint64(lengths[:8], c.adlen)
	binary.BigEndian.PutUint64(lengths[8:], c.count)
	c.sign.Write(lengths[:])
}

type encrypter struct{ crypter[sign.Signer] }

func (c *encrypter) Encrypt(dst, src []byte) {
	c.ciph.XORKeyStream(dst, src)
	c.write(dst[:len(src)])
}

func (c *encrypter) Sign() []byte {
	c.finalize()
	return c.sign.Sign()
}

type decrypter struct{ crypter[sign.Verifier] }

func (c *decrypter) Decrypt(dst, src []byte) {
	if len(src) > len(dst) {
		panic("ssaed: dst is too short")
	}
	c.write(src)
	c.ciph.XORKeyStream(dst, src)
}

func (c *decrypter) Verify(signature []byte) (bool, error) {
	c.finalize()
	return c.sign.Verify(signature)
}
