package quark

import "github.com/karalef/quark/pack"

// packet tags.
const (
	PacketTagIdentity pack.Tag = 0x01
)

func init() {
	pack.RegisterPacketType(packetTypeIdentity)
}

var (
	packetTypeIdentity = pack.NewType(
		(*Identity)(nil),
		"identity",
		"QUARK IDENTITY",
	)
)
