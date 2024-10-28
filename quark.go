package quark

import "github.com/karalef/quark/pack"

// packet tags.
const (
	PacketTagKey pack.Tag = 0x01
)

func init() {
	pack.RegisterPacketType(packetTypeKey)
}

var (
	packetTypeKey = pack.NewType(
		(*Key)(nil),
		"key",
		"QUARK KEY",
	)
)
