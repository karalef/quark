package ae

import (
	"github.com/karalef/quark/crypto/cipher"
	"github.com/karalef/quark/crypto/mac"
	"github.com/karalef/quark/crypto/xof"
)

// Build creates an AE scheme with the given approach.
// Panics if one of the arguments is nil.
func Build(approach Approach, cipher cipher.Scheme, mac mac.Scheme, xof xof.XOF) Scheme {
	if cipher == nil || mac == nil || xof == nil {
		panic("ae.Build: nil scheme part")
	}
	return &scheme{
		cipher:   cipher,
		mac:      mac,
		xof:      xof,
		approach: approach,
	}
}

var _ Scheme = (*scheme)(nil)

type scheme struct {
	cipher   cipher.Scheme
	mac      mac.Scheme
	xof      xof.XOF
	approach Approach
}

func (s *scheme) Approach() Approach    { return s.approach }
func (s *scheme) Cipher() cipher.Scheme { return s.cipher }
func (s *scheme) MAC() mac.Scheme       { return s.mac }
func (s *scheme) XOF() xof.XOF          { return s.xof }

func (s *scheme) Encrypter(ss, iv []byte) (AE, error) { return NewEncrypter(s, ss, iv) }
func (s *scheme) Decrypter(ss, iv []byte) (AE, error) { return NewDecrypter(s, ss, iv) }
