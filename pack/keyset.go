package pack

import (
	"io"

	"github.com/karalef/quark"
)

// PackedKeyset represent a good form for keyset encoding/decoding.
type PackedKeyset struct {
	IsPrivate bool
	Identity  quark.Identity
	Scheme    string
	SignKey   []byte
	KEMKey    []byte
}

// UnpackPrivate makes private keyset from packed keyset.
func (p PackedKeyset) UnpackPrivate() (quark.PrivateKeyset, error) {
	sch, err := quark.ParseScheme(p.Scheme)
	if err != nil {
		return nil, err
	}
	kemPriv, err := sch.KEM.UnpackPrivate(p.KEMKey)
	if err != nil {
		return nil, err
	}
	signPriv, err := sch.Sign.UnpackPrivate(p.SignKey)
	if err != nil {
		return nil, err
	}
	return quark.NewPrivateKeyset(p.Identity, kemPriv, sch.Cipher, signPriv, sch.Hash)
}

// UnpackPublic makes public keyset from prepacked keyset.
func (p PackedKeyset) UnpackPublic() (quark.PublicKeyset, error) {
	sch, err := quark.ParseScheme(p.Scheme)
	if err != nil {
		return nil, err
	}
	kemPub, err := sch.KEM.UnpackPublic(p.KEMKey)
	if err != nil {
		return nil, err
	}
	signPub, err := sch.Sign.UnpackPublic(p.SignKey)
	if err != nil {
		return nil, err
	}
	return quark.NewPublicKeyset(p.Identity, kemPub, sch.Cipher, signPub, sch.Hash)
}

func prepackPrivate(s quark.PrivateKeyset) PackedKeyset {
	return PackedKeyset{
		IsPrivate: true,
		Identity:  s.Identity(),
		Scheme:    quark.SchemeOf(s).String(),
		SignKey:   s.SignPrivateKey().Pack(),
		KEMKey:    s.KEMPrivateKey().Pack(),
	}
}

func prepackPublic(s quark.PublicKeyset) PackedKeyset {
	return PackedKeyset{
		IsPrivate: false,
		Identity:  s.Identity(),
		Scheme:    quark.SchemeOf(s).String(),
		SignKey:   s.SignPublicKey().Pack(),
		KEMKey:    s.KEMPublicKey().Pack(),
	}
}

// Private packs a private keyset into a binary format.
func Private(out io.Writer, s quark.PrivateKeyset) error {
	return Pack(out, prepackPrivate(s))
}

// Public packs a public keyset into a binary format.
func Public(out io.Writer, s quark.PublicKeyset) error {
	return Pack(out, prepackPublic(s))
}

// UnpackPrivate unpacks a private keyset from a binary format.
func UnpackPrivate(in io.Reader) (quark.PrivateKeyset, error) {
	var p PackedKeyset
	if err := Unpack(in, &p); err != nil {
		return nil, err
	}
	return p.UnpackPrivate()
}

// UnpackPublic unpacks a public keyset from a binary format.
func UnpackPublic(in io.Reader) (quark.PublicKeyset, error) {
	var p PackedKeyset
	if err := Unpack(in, &p); err != nil {
		return nil, err
	}
	return p.UnpackPublic()
}

// keyset block types
const (
	BlockTypePublic  = "QUARK PUBLIC KEYSET"
	BlockTypePrivate = "QUARK PRIVATE KEYSET"
)

// PrivateArmor packs a private keyset into an OpenPGP armored block.
func PrivateArmor(out io.Writer, s quark.PrivateKeyset) error {
	return Armored(out, prepackPrivate(s), BlockTypePrivate, nil)
}

// PublicArmor packs a public keyset into an OpenPGP armored block.
func PublicArmor(out io.Writer, s quark.PublicKeyset) error {
	return Armored(out, prepackPublic(s), BlockTypePublic, nil)
}

// UnpackPrivateArmor unpacks a private keyset from an OpenPGP armored block.
func UnpackPrivateArmor(in io.Reader) (quark.PrivateKeyset, error) {
	var p PackedKeyset
	if _, _, err := UnpackArmored(in, &p, BlockTypePrivate); err != nil {
		return nil, err
	}
	return p.UnpackPrivate()
}

// UnpackPublicArmor unpacks a public keyset from an OpenPGP armored block.
func UnpackPublicArmor(in io.Reader) (quark.PublicKeyset, error) {
	var p PackedKeyset
	if _, _, err := UnpackArmored(in, &p, BlockTypePublic); err != nil {
		return nil, err
	}
	return p.UnpackPublic()
}
