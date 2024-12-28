package config

import (
	"io"
	"runtime"

	"github.com/karalef/quark/crypto/aead"
	"github.com/karalef/quark/crypto/kdf"
	"github.com/karalef/quark/crypto/xof"
	"github.com/karalef/quark/extensions/message/compress"
	"gopkg.in/yaml.v3"
)

const (
	// FileExtension is the file extension for the packed data.
	FileExtension = "quark"

	// PrivateKeyExtension is the file extension for the private key.
	PrivateKeyExtension = "key"

	// KeyExtension is the file extension for the public key.
	KeyExtension = "qk"
)

type Config struct {
	// global
	CipherKDF `yaml:",inline"`

	Messages Messages  `yaml:"messages,omitempty"`
	Local    CipherKDF `yaml:"local,omitempty"`
	Backup   CipherKDF `yaml:"backup,omitempty"`
}

type Messages struct {
	XOF         XOF         `yaml:"xof,omitempty"`
	Compression Compression `yaml:"compression,omitempty"`
	CipherKDF   `yaml:",inline"`
}

type CipherKDF struct {
	Cipher Cipher `yaml:"cipher,omitempty"`
	KDF    KDF    `yaml:"kdf,omitempty"`
}

type Compression struct {
	Algorithm compressAlg `yaml:"algorithm,omitempty"`
	Lvl       uint        `yaml:"level,omitempty"`
	Threads   uint        `yaml:"threads,omitempty"`
}

type KDF struct {
	Default  kdfAlg         `yaml:"default,omitempty"`
	Argon2i  kdf.Argon2Cost `yaml:"argon2i,omitempty"`
	Scrypt   kdf.ScryptCost `yaml:"scrypt,omitempty"`
	Argon2id kdf.Argon2Cost `yaml:"argon2id,omitempty"`
	SaltSize uint8          `yaml:"salt_size,omitempty"`
}

func Load(r io.Reader) (Config, error) {
	var cfg Config
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(w io.Writer, cfg Config) error {
	return yaml.NewEncoder(w).Encode(cfg)
}

var maxprocs = runtime.GOMAXPROCS(0)

var Default = Config{
	CipherKDF: CipherKDF{
		Cipher: Cipher{Scheme: aead.ChaCha20Poly1305},
		KDF: KDF{
			Default: kdfAlg{kdf.Argon2i},
			Argon2i: kdf.Argon2Cost{
				Time:    1,
				Memory:  16 * 1024,
				Threads: uint8(maxprocs),
			},
			Argon2id: kdf.Argon2Cost{
				Time:    1,
				Memory:  16 * 1024,
				Threads: uint8(maxprocs),
			},
			Scrypt: kdf.ScryptCost{
				N: 1 << 15,
				R: 1 << 3,
				P: 1,
			},
			SaltSize: 16,
		},
	},
	Messages: Messages{
		XOF: XOF{Scheme: xof.BLAKE3x},
		Compression: Compression{
			Algorithm: compressAlg{compress.LZ4},
			Lvl:       compress.LZ4.DefaultLevel(),
			Threads:   uint(maxprocs),
		},
	},
	Local: CipherKDF{
		KDF: KDF{
			Argon2i: kdf.Argon2Cost{
				Time:    2,
				Memory:  1024 * 1024,
				Threads: uint8(maxprocs),
			},
		},
	},
}
