package quark

import "github.com/karalef/quark/pack"

// packet tags.
const (
	PacketTagPrivateKey pack.Tag = 0x01
	PacketTagIdentity   pack.Tag = 0x02
)

func init() {
	pack.RegisterPacketType(packetTypePrivateKey)
	pack.RegisterPacketType(packetTypeIdentity)
}

var (
	packetTypePrivateKey = pack.NewType(
		(*EncryptedKey)(nil),
		"private key",
		"QUARK PRIVATE KEY",
	)

	packetTypeIdentity = pack.NewType(
		(*identity)(nil),
		"identity",
		"QUARK IDENTITY",
	)
)
