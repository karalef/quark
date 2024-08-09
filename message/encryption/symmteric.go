package encryption

import (
	"errors"
	"strings"

	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/password"
	"github.com/karalef/quark/crypto/secret"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/pack"
)

// Symmetric precedes the encrypted data and contains
// enough information to allow the receiver to begin decryption
// and calculation authentication tag.
type Symmetric struct {
	Password *Password `msgpack:"password,omitempty"`
	XOF      *XOF      `msgpack:"xof,omitempty"`

	IV     []byte       `msgpack:"iv"`
	Scheme StreamScheme `msgpack:"scheme"`
}

var _ pack.CustomEncoder = (*XOF)(nil)
var _ pack.CustomDecoder = (*XOF)(nil)

// XOF represents a XOF algorithm.
type XOF struct {
	xof.XOF
}

// EncodeMsgpack implements pack.CustomEncoder.
func (x XOF) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(strings.ToUpper(x.Name()))
}

// DecodeMsgpack implements pack.CustomDecoder.
func (x *XOF) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	x.XOF = xof.ByName(str)
	if x.XOF == nil {
		err = errInvalidSymmetricScheme
	}
	return nil
}

var _ pack.CustomEncoder = (*Password)(nil)
var _ pack.CustomDecoder = (*Password)(nil)

// Password contains password-based authenticated encryption parameters.
type Password struct {
	KDF    kdf.KDF
	Params kdf.Params
	Salt   []byte
}

// EncodeMsgpack implements the pack.CustomEncoder interface.
func (p Password) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeMap(map[string]interface{}{
		"kdf":    p.KDF.Name(),
		"params": p.Params.Encode(),
		"salt":   p.Salt,
	})
}

// DecodeMsgpack implements the pack.CustomDecoder interface.
func (p *Password) DecodeMsgpack(dec *pack.Decoder) error {
	m, err := dec.DecodeMap()
	if err != nil {
		return err
	}

	p.KDF = kdf.ByName(m["kdf"].(string))
	if p.KDF == nil {
		return errInvalidSymmetricScheme
	}
	p.Params = p.KDF.NewParams()
	if err := p.Params.Decode(m["params"].([]byte)); err != nil {
		return err
	}
	p.Salt = m["salt"].([]byte)

	return nil
}

var _ pack.CustomEncoder = StreamScheme{}
var _ pack.CustomDecoder = (*StreamScheme)(nil)

// StreamScheme represents an AEAD encryption scheme.
type StreamScheme struct {
	aead.Scheme
}

func (s StreamScheme) String() string {
	return strings.ToUpper(s.Cipher().Name() + "-" + s.MAC().Name())
}

// EncodeMsgpack implements pack.CustomEncoder.
func (s StreamScheme) EncodeMsgpack(enc *pack.Encoder) error {
	return enc.EncodeString(s.String())
}

// Parse parses a symmetric encryption scheme.
func (s *StreamScheme) Parse(str string) error {
	cipherAlg, macAlg, ok := strings.Cut(str, "-")
	if !ok {
		return errInvalidSymmetricScheme
	}

	cipher := cipher.ByName(cipherAlg)
	mac := mac.ByName(macAlg)
	if cipher == nil || mac == nil {
		return errInvalidSymmetricScheme
	}
	s.Scheme = aead.Build(cipher, mac)
	return nil
}

// DecodeMsgpack implements pack.CustomDecoder.
func (s *StreamScheme) DecodeMsgpack(dec *pack.Decoder) error {
	str, err := dec.DecodeString()
	if err != nil {
		return err
	}
	return s.Parse(str)
}

// Encrypt creates a new AEAD cipher using shared secret.
func Encrypt(scheme secret.Scheme, sharedSecret, associatedData []byte) (aead.Cipher, *Encryption, error) {
	iv := crypto.Rand(scheme.AEAD().Cipher().IVSize())

	aead, err := scheme.Encrypter(iv, sharedSecret, associatedData)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Symmetric: Symmetric{
			XOF:    &XOF{scheme.XOF()},
			IV:     iv,
			Scheme: StreamScheme{scheme.AEAD()},
		},
	}, nil
}

// PasswordEncrypt creates a new AEAD cipher using passphrase.
func PasswordEncrypt(scheme password.Scheme, passphrase string, associatedData []byte, params kdf.Params) (aead.Cipher, *Encryption, error) {
	iv := crypto.Rand(scheme.AEAD().Cipher().IVSize())
	salt := crypto.Rand(16)

	aead, err := scheme.Encrypter(passphrase, iv, salt, associatedData, params)
	if err != nil {
		return nil, nil, err
	}

	return aead, &Encryption{
		Symmetric: Symmetric{
			Password: &Password{
				KDF:    scheme.KDF(),
				Params: params,
				Salt:   salt,
			},
			IV:     iv,
			Scheme: StreamScheme{scheme.AEAD()},
		},
	}, nil
}

// Decrypt creates a new AEAD cipher using shared secret.
func (s Symmetric) Decrypt(sharedSecret, associatedData []byte) (aead.Cipher, error) {
	return secret.Build(s.Scheme, s.XOF.XOF).Decrypter(s.IV, sharedSecret, associatedData)
}

// PasswordDecrypt creates a new AEAD cipher using passphrase.
func (s Symmetric) PasswordDecrypt(passphrase string, associatedData []byte) (aead.Cipher, error) {
	scheme := password.Build(s.Scheme, s.Password.KDF)
	return scheme.Decrypter(passphrase, s.IV, s.Password.Salt, associatedData, s.Password.Params)
}

var errInvalidSymmetricScheme = errors.New("invalid symmetric encryption scheme")
