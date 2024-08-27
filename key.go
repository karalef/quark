package quark

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
)

type (
	ID          = crypto.ID
	Fingerprint = crypto.Fingerprint

	PublicKey  = sign.PublicKey
	PrivateKey = sign.PrivateKey
)

var (
	ErrKeyNotCorrespond = crypto.ErrKeyNotCorrespond
)
