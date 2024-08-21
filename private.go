package quark

import (
	"errors"
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/pack"
)

func EncryptKey(p *PrivateKey, passphrase string, scheme password.Scheme, kdfParams kdf.Params) (*EncryptedKey, error) {
	if p == nil || scheme == nil || kdfParams == nil || passphrase == "" {
		return nil, errors.New("invalid parameters")
	}
	alg := p.Scheme().Name()
	key := p.Raw().Pack()

	salt := crypto.Rand(32)
	iv := crypto.Rand(scheme.AEAD().Cipher().IVSize())
	cipher, err := scheme.Encrypter(passphrase, iv, salt, []byte(alg), kdfParams)
	if err != nil {
		return nil, err
	}

	cipher.Crypt(key, key)

	return &EncryptedKey{
		Fingerprint: p.Fingerprint(),
		Scheme:      p.Scheme(),
		Key:         key,
		IV:          iv,
		Salt:        salt,
		Tag:         cipher.Tag(nil),
		PassScheme:  scheme,
		KDFParams:   kdfParams,
	}, nil
}

var _ pack.CustomEncoder = (*EncryptedKey)(nil)
var _ pack.CustomDecoder = (*EncryptedKey)(nil)

// EncryptedKey is used to store the private key encrypted with passphrase.
type EncryptedKey struct {
	Fingerprint Fingerprint
	Scheme      sign.Scheme
	Key         []byte

	IV         []byte
	Salt       []byte
	Tag        []byte
	PassScheme password.Scheme
	KDFParams  kdf.Params
}

// PacketTag implements pack.Packable interface.
func (*EncryptedKey) PacketTag() pack.Tag { return PacketTagPrivateKey }

// EncodeMsgpack implements pack.CustomEncoder interface.
func (p *EncryptedKey) EncodeMsgpack(enc *pack.Encoder) error {
	if p.KDFParams == nil || p.PassScheme == nil || p.IV == nil || p.Salt == nil {
		return errors.New("invalid key")
	}
	return enc.EncodeMap(map[string]interface{}{
		"fp":         p.Fingerprint,
		"algorithm":  p.Scheme.Name(),
		"key":        p.Key,
		"iv":         p.IV,
		"salt":       p.Salt,
		"tag":        p.Tag,
		"scheme":     p.PassScheme.AEAD().Cipher().Name() + "-" + p.PassScheme.AEAD().MAC().Name() + "-" + p.PassScheme.KDF().Name(),
		"kdf_params": p.KDFParams.Encode(),
	})
}

// DecodeMsgpack implements pack.CustomDecoder interface.
func (p *EncryptedKey) DecodeMsgpack(dec *pack.Decoder) error {
	m, err := dec.DecodeMap()
	if err != nil {
		return err
	}

	p.Fingerprint = m["fp"].(Fingerprint)
	p.Scheme = sign.ByName(m["algorithm"].(string))
	p.Key = m["key"].([]byte)
	p.IV = m["iv"].([]byte)
	p.Salt = m["salt"].([]byte)
	p.Tag = m["tag"].([]byte)

	parts := strings.SplitN(m["scheme"].(string), "-", 3)
	if len(parts) != 3 {
		return UnpackError("invalid scheme: " + m["scheme"].(string))
	}
	p.PassScheme = password.Build(aead.Build(cipher.ByName(parts[0]), mac.ByName(parts[1])), kdf.ByName(parts[2]))
	params := p.PassScheme.KDF().NewParams()
	if err := params.Decode(m["kdf_params"].([]byte)); err != nil {
		return err
	}
	p.KDFParams = params
	return nil
}

func (p *EncryptedKey) Decrypt(passphrase string) (*PrivateKey, error) {
	cipher, err := p.PassScheme.Decrypter(passphrase, p.IV, p.Salt, []byte(p.Scheme.Name()), p.KDFParams)
	if err != nil {
		return nil, err
	}

	key := make([]byte, p.Scheme.PrivateKeySize())
	cipher.Crypt(key, p.Key)
	tag := cipher.Tag(nil)
	if !mac.Equal(p.Tag, tag) {
		return nil, mac.ErrMismatch
	}

	priv, err := p.Scheme.UnpackPrivate(key)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		sk: priv,
		pk: &PublicKey{
			pk: priv.Public(),
		},
	}, nil
}

type PrivateKey struct {
	sk sign.PrivateKey
	pk *PublicKey
}

func (p *PrivateKey) ID() ID                   { return p.Public().ID() }
func (p *PrivateKey) Fingerprint() Fingerprint { return p.Public().Fingerprint() }
func (p *PrivateKey) Scheme() sign.Scheme      { return p.sk.Scheme() }
func (p *PrivateKey) Sign(data []byte) []byte  { return p.sk.Sign(data) }
func (p *PrivateKey) Raw() sign.PrivateKey     { return p.sk }

func (p *PrivateKey) Public() *PublicKey {
	if p.pk == nil {
		p.pk = &PublicKey{pk: p.sk.Public()}
	}
	return p.pk
}
