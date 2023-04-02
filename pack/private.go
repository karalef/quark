package pack

import (
	"io"

	"github.com/karalef/quark"
)

type PackedPrivate struct {
	PackedPublic
	SignPrivKey []byte
	KEMPrivKey  []byte
}

func (p PackedPrivate) Load() (quark.PrivateKeyset, error) {
	pub, err := p.PackedPublic.Load()
	if err != nil {
		return nil, err
	}

	kemPriv, err := pub.KEMPublicKey().Scheme().UnpackPrivate(p.KEMPrivKey)
	if err != nil {
		return nil, err
	}
	signPriv, err := pub.SignPublicKey().Scheme().UnpackPrivate(p.SignPrivKey)
	if err != nil {
		return nil, err
	}

	return quark.NewPrivateKeyset(pub, kemPriv, signPriv)
}

func PrepackPrivate(p quark.PrivateKeyset) PackedPrivate {
	return PackedPrivate{
		PackedPublic: PrepackPublic(p),
		SignPrivKey:  p.SignPrivateKey().Bytes(),
		KEMPrivKey:   p.KEMPrivateKey().Bytes(),
	}
}

func Private(out io.Writer, p quark.PrivateKeyset) error {
	return Pack(out, PrepackPrivate(p))
}

func PreunpackPrivate(in io.Reader) (PackedPrivate, error) {
	var p PackedPrivate
	if err := Unpack(in, &p); err != nil {
		return PackedPrivate{}, err
	}
	return p, nil
}

func UnpackPrivate(in io.Reader) (quark.PrivateKeyset, error) {
	p, err := PreunpackPrivate(in)
	if err != nil {
		return nil, err
	}

	return p.Load()
}
