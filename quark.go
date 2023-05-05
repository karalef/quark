package quark

import "github.com/karalef/quark/pack"

// packet tags.
const (
	PacketTagMessage       pack.Tag = 0x01
	PacketTagPublicKeyset  pack.Tag = 0x02
	PacketTagPrivateKeyset pack.Tag = 0x03
)

func init() {
	pack.RegisterPacketType(packetTypeMessage)
	pack.RegisterPacketType(packetTypePublicKeyset)
	pack.RegisterPacketType(packetTypePrivateKeyset)
}

var (
	packetTypeMessage = pack.NewType(
		PacketTagMessage,
		(*Message)(nil),
		"message",
		"QUARK MESSAGE",
	)

	packetTypePublicKeyset = pack.NewType(
		PacketTagPublicKeyset,
		(*Public)(nil),
		"public keyset",
		"QUARK PUBLIC KEYSET",
	)

	packetTypePrivateKeyset = pack.NewType(
		PacketTagPrivateKeyset,
		(*Private)(nil),
		"private keyset",
		"QUARK PRIVATE KEYSET",
	)
)
