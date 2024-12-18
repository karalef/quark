package kyber

import (
	"github.com/cloudflare/circl/pke/kyber/kyber1024"
	"github.com/cloudflare/circl/pke/kyber/kyber512"
	"github.com/cloudflare/circl/pke/kyber/kyber768"
)

var Kyber512 Scheme = kyberScheme[*kyber512.PublicKey, *kyber512.PrivateKey]{
	derive: kyber512.NewKeyFromSeed,
	public: func(b []byte) *kyber512.PublicKey {
		var pk kyber512.PublicKey
		pk.Unpack(b)
		return &pk
	},
	private: func(key []byte) *kyber512.PrivateKey {
		var sk kyber512.PrivateKey
		sk.Unpack(key)
		return &sk
	},
	sk: kyber512.PrivateKeySize,
	pk: kyber512.PublicKeySize,
	ct: kyber512.CiphertextSize,
	pt: kyber512.PlaintextSize,
	es: kyber512.EncryptionSeedSize,
	s:  kyber512.KeySeedSize,
}

var Kyber768 Scheme = kyberScheme[*kyber768.PublicKey, *kyber768.PrivateKey]{
	derive: kyber768.NewKeyFromSeed,
	public: func(b []byte) *kyber768.PublicKey {
		var pk kyber768.PublicKey
		pk.Unpack(b)
		return &pk
	},
	private: func(key []byte) *kyber768.PrivateKey {
		var sk kyber768.PrivateKey
		sk.Unpack(key)
		return &sk
	},
	sk: kyber768.PrivateKeySize,
	pk: kyber768.PublicKeySize,
	ct: kyber768.CiphertextSize,
	pt: kyber768.PlaintextSize,
	es: kyber768.EncryptionSeedSize,
	s:  kyber768.KeySeedSize,
}

var Kyber1024 Scheme = kyberScheme[*kyber1024.PublicKey, *kyber1024.PrivateKey]{
	derive: kyber1024.NewKeyFromSeed,
	public: func(b []byte) *kyber1024.PublicKey {
		var pk kyber1024.PublicKey
		pk.Unpack(b)
		return &pk
	},
	private: func(key []byte) *kyber1024.PrivateKey {
		var sk kyber1024.PrivateKey
		sk.Unpack(key)
		return &sk
	},
	sk: kyber1024.PrivateKeySize,
	pk: kyber1024.PublicKeySize,
	ct: kyber1024.CiphertextSize,
	pt: kyber1024.PlaintextSize,
	es: kyber1024.EncryptionSeedSize,
	s:  kyber1024.KeySeedSize,
}
