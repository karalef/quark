package quark

import (
	"crypto/md5"
	"encoding/hex"

	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

// IDFromString creates keyset ID from string.
// It returns false if the string is not a valid keyset ID.
func IDFromString(strID string) (id ID, ok bool) {
	if len(strID) != idStringSize {
		return
	}
	_, err := hex.Decode(id[:], []byte(strID))
	return id, err == nil
}

const idStringSize = 8 * 2 // hexed id

// ID represents keyset ID.
type ID [8]byte

func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

func calculateFingerprint(sign sign.PublicKey, kem kem.PublicKey) Fingerprint {
	md5 := md5.New()
	md5.Write(sign.Bytes())
	md5.Write(kem.Bytes())
	return Fingerprint(md5.Sum(nil))
}

// Fingerprint represents keyset fingerprint.
type Fingerprint [md5.Size]byte

// ID calculates keyset ID from fingerprint.
func (f Fingerprint) ID() ID {
	return ID(f[:8])
}

func (f Fingerprint) String() string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, len(f)*3)
	for i := 0; i < len(f); i++ {
		buf = append(buf, hex[f[i]>>4], hex[f[i]&0xf], ':')
	}
	return string(buf[:len(buf)-1])
}
