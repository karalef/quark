package quark

import (
	"errors"

	"github.com/karalef/quark/keys"
	"github.com/karalef/quark/keys/sign"
)

// id sizes.
const (
	IDSize       = keys.IDSize
	IDStringSize = keys.IDStringSize
	FPSize       = keys.FPSize
	FPStringSize = keys.FPStringSize
)

type (
	ID          = keys.ID
	Fingerprint = keys.Fingerprint

	PublicKey    = sign.PublicKey
	PrivateKey   = sign.PrivateKey
	EncryptedKey = sign.Encrypted
)

// key errors.
var (
	ErrKeyNotCorrespond = errors.New("the public key does not correspond to the private key")
)
