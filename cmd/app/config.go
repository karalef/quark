package app

import (
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/encrypted"
	"github.com/karalef/quark/encrypted/password"
)

func (a *App) PassphraseParams(scheme password.Scheme) encrypted.PassphraseParams {
	var cost kdf.Cost
	switch scheme.KDF().Name() {
	case kdf.Argon2i.Name():
		cost = &a.cfg.KDF.Argon2i
	case kdf.Argon2id.Name():
		cost = &a.cfg.KDF.Argon2id
	case kdf.Scrypt.Name():
		cost = &a.cfg.KDF.Scrypt
	}
	return encrypted.PassphraseParams{
		Scheme:   scheme,
		Cost:     cost,
		SaltSize: int(a.cfg.KDF.SaltSize),
	}
}
