package pack

import (
	"errors"
	"io"

	"github.com/karalef/quark"
)

type KeysetData struct {
	Fingerprint quark.Fingerprint
	Identity    quark.Identity
	Scheme      string
}

// PackedPublic represent a good form for public keyset encoding/decoding.
type PackedPublic struct {
	KeysetData
	SignPubKey []byte
	KEMPubKey  []byte
}

func (p PackedPublic) Load() (quark.PublicKeyset, error) {
	sch, err := quark.ParseScheme(p.Scheme)
	if err != nil {
		return nil, err
	}

	kemPub, err := sch.KEM.UnpackPublic(p.KEMPubKey)
	if err != nil {
		return nil, err
	}
	signPub, err := sch.Sign.UnpackPublic(p.SignPubKey)
	if err != nil {
		return nil, err
	}
	pub, err := quark.NewPublicKeyset(p.Identity, kemPub, sch.Cipher, signPub, sch.Hash)
	if err != nil {
		return nil, err
	}

	// verify fp
	if p.Fingerprint != quark.FingerprintOf(pub) {
		return nil, errors.New("invalid fingerprint")
	}
	return pub, nil
}

func PrepackPublic(p quark.PublicKeyset) PackedPublic {
	return PackedPublic{
		KeysetData: KeysetData{
			Fingerprint: quark.FingerprintOf(p),
			Identity:    p.Identity(),
			Scheme:      quark.SchemeOf(p).String(),
		},
		SignPubKey: p.SignPublicKey().Bytes(),
		KEMPubKey:  p.KEMPublicKey().Bytes(),
	}
}

// Public packs a public keyset into a binary format.
func Public(out io.Writer, s quark.PublicKeyset) error {
	return Pack(out, PrepackPublic(s))
}

func PreunpackPublic(in io.Reader) (PackedPublic, error) {
	var p PackedPublic
	if err := Unpack(in, &p); err != nil {
		return PackedPublic{}, err
	}
	return p, nil
}

func UnpackPublic(in io.Reader) (quark.PublicKeyset, error) {
	p, err := PreunpackPublic(in)
	if err != nil {
		return nil, err
	}
	return p.Load()
}

// keyset block types
const (
	BlockTypePublic  = "QUARK PUBLIC KEYSET"
	BlockTypePrivate = "QUARK PRIVATE KEYSET"
)
