package pack

import (
	"errors"
	"io"

	"github.com/karalef/quark"
)

// keyset block types
const (
	BlockTypePublic  = "QUARK PUBLIC KEYSET"
	BlockTypePrivate = "QUARK PRIVATE KEYSET"
)

var (
	typePublic = MsgType{
		Tag:       TagPublicKeyset,
		BlockType: BlockTypePublic,
		Unpacker:  unpackPublic,
	}
	typePrivate = MsgType{
		Tag:       TagPrivateKeyset,
		BlockType: BlockTypePrivate,
		Unpacker:  unpackPrivate,
	}
)

type keysetData struct {
	Fingerprint quark.Fingerprint `msgpack:"fp"`
	Scheme      string            `msgpack:"scheme"`
	Name        string            `msgpack:"name,omitempty"`
	Email       string            `msgpack:"email,omitempty"`
}

func (d keysetData) data() (quark.Scheme, quark.Identity, error) {
	sch, err := quark.ParseScheme(d.Scheme)
	if err != nil {
		return sch, quark.Identity{}, err
	}
	return sch, quark.Identity{
		Name:  d.Name,
		Email: d.Email,
	}, nil
}

func packKeysetData(ks *quark.Public) keysetData {
	id := ks.Identity()
	return keysetData{
		Fingerprint: ks.Fingerprint(),
		Scheme:      ks.Scheme().String(),
		Name:        id.Name,
		Email:       id.Email,
	}
}

var _ Packable = packedPublic{}

type packedPublic struct {
	keysetData `msgpack:",inline"`
	SignPub    []byte `msgpack:"sign_pub"`
	KEMPub     []byte `msgpack:"kem_pub"`
}

func (packedPublic) Type() MsgType { return typePublic }

// Public packs a public keyset into a binary format.
func Public(out io.Writer, p *quark.Public) error {
	return Pack(out, packedPublic{
		keysetData: packKeysetData(p),
		SignPub:    p.Sign().Bytes(),
		KEMPub:     p.KEM().Bytes(),
	})
}

func unpackPublic(in io.Reader) (any, error) {
	p, err := unpack[packedPublic](in)
	if err != nil {
		return nil, err
	}

	sch, id, err := p.keysetData.data()
	if err != nil {
		return nil, err
	}

	kemPub, err := sch.KEM.UnpackPublic(p.KEMPub)
	if err != nil {
		return nil, err
	}
	signPub, err := sch.Sign.UnpackPublic(p.SignPub)
	if err != nil {
		return nil, err
	}
	pub, err := quark.NewPublic(id, kemPub, signPub, sch.Hash)
	if err != nil {
		return nil, err
	}

	// verify fp
	if p.Fingerprint != pub.Fingerprint() {
		return nil, errors.New("invalid fingerprint")
	}
	return pub, nil
}

var _ Packable = packedPrivate{}

type packedPrivate struct {
	keysetData `msgpack:",inline"`
	SignSeed   []byte `msgpack:"sign_seed"`
	KEMSeed    []byte `msgpack:"kem_seed"`
}

func (packedPrivate) Type() MsgType { return typePrivate }

// Private packs a private keyset into a binary format.
func Private(out io.Writer, p *quark.Private) error {
	signSeed, kemSeed := p.Seeds()
	return Pack(out, packedPrivate{
		keysetData: packKeysetData(p.Public()),
		SignSeed:   signSeed,
		KEMSeed:    kemSeed,
	})
}

func unpackPrivate(in io.Reader) (any, error) {
	p, err := unpack[packedPrivate](in)
	if err != nil {
		return nil, err
	}

	sch, id, err := p.keysetData.data()
	if err != nil {
		return nil, err
	}

	return quark.NewPrivate(id, sch, p.SignSeed, p.KEMSeed)
}
