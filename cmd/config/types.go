package config

import (
	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/extensions/message/compress"
	"gopkg.in/yaml.v3"
)

type ctype interface {
	yaml.Marshaler
	yaml.Unmarshaler
	yaml.IsZeroer
}

var _ ctype = (*kdfAlg)(nil)

type kdfAlg struct{ kdf.Scheme }

func (k kdfAlg) IsZero() bool              { return k.Scheme == nil }
func (k kdfAlg) MarshalYAML() (any, error) { return k.Scheme.Name(), nil }

func (k *kdfAlg) UnmarshalYAML(node *yaml.Node) (err error) {
	k.Scheme, err = kdf.ByName(node.Value)
	return err
}

var _ ctype = (*Cipher)(nil)

type Cipher struct{ aead.Scheme }

func (c Cipher) IsZero() bool              { return c.Scheme == nil }
func (c Cipher) MarshalYAML() (any, error) { return c.Scheme.Name(), nil }

func (c *Cipher) UnmarshalYAML(node *yaml.Node) (err error) {
	c.Scheme, err = aead.ByName(node.Value)
	return err
}

var _ ctype = (*XOF)(nil)

type XOF struct{ xof.Scheme }

func (x XOF) IsZero() bool              { return x.Scheme == nil }
func (x XOF) MarshalYAML() (any, error) { return x.Scheme.Name(), nil }

func (x *XOF) UnmarshalYAML(node *yaml.Node) (err error) {
	x.Scheme, err = xof.ByName(node.Value)
	return err
}

var _ ctype = (*compressAlg)(nil)

type compressAlg struct{ compress.Compression }

func (c compressAlg) IsZero() bool              { return c.Compression == nil }
func (c compressAlg) MarshalYAML() (any, error) { return c.Compression.Name(), nil }

func (c *compressAlg) UnmarshalYAML(node *yaml.Node) (err error) {
	c.Compression, err = compress.ByName(node.Value)
	return err
}
