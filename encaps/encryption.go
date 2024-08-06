package encaps

import (
	"github.com/karalef/quark/crypto"
)

// Encapsulate generates and encapsulates a shared secret.
func Encapsulate(recipient PublicKey) (encapsed, secret []byte, err error) {
	return recipient.Encapsulate(crypto.Rand(recipient.Scheme().EncapsulationSeedSize()))
}
