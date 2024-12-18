package quark

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/pack"
)

// packet tags.
const (
	PacketTagCertificate pack.Tag = 0x01
	PacketTagPublicKey   pack.Tag = 0x02
	PacketTagPrivateKey  pack.Tag = 0x03
	PacketTagKey         pack.Tag = 0x04
)

func init() {
	pack.RegisterPacketType(pack.NewType(
		(*Raw)(nil),
		"certificate",
		"QUARK CERTIFICATE",
	))
	pack.RegisterPacketType(pack.NewType(
		(*PublicKey[crypto.Key])(nil),
		"public key",
		"QUARK PUBLIC KEY",
	))
	pack.RegisterPacketType(pack.NewType(
		(*PrivateKey[crypto.Key])(nil),
		"private key",
		"QUARK PRIVATE KEY",
	))
	pack.RegisterPacketType(pack.NewType(
		(*Key)(nil),
		"key",
		"QUARK KEY",
	))
}
