package quark

import (
	"github.com/karalef/quark/crypto"
	"github.com/karalef/quark/crypto/sign"
	"github.com/karalef/quark/keys"
)

type (
	ID          = crypto.ID
	Fingerprint = crypto.Fingerprint

	PublicKey    = sign.PublicKey
	PrivateKey   = sign.PrivateKey
	EncryptedKey = keys.Encrypted
)

var (
	ErrKeyNotCorrespond = crypto.ErrKeyNotCorrespond
)
