package quark

import (
	"crypto/md5"
	"encoding/hex"
)

// KeysetIDOf returns keyset ID of a public keyset.
func KeysetIDOf(p PublicKeyset) KeysetID {
	return KeysetIDByFP(FingerprintOf(p))
}

// KeysetIDBytes returns keyset ID of a byte slice.
func KeysetIDBytes(b []byte) KeysetID {
	return KeysetIDByFP(FingerprintBytes(b))
}

// KeysetIDByFP calculates keyset ID by fingerprint.
func KeysetIDByFP(fp Fingerprint) KeysetID {
	return KeysetID(fp[:8])
}

// FingerprintOf returns fingerprint of a keyset.
func FingerprintOf(p PublicKeyset) Fingerprint {
	md5 := md5.New()
	md5.Write(p.SignPublicKey().Bytes())
	md5.Write(p.KEMPublicKey().Bytes())
	return Fingerprint(md5.Sum(nil))
}

// FingerprintBytes returns fingerprint of a byte slice.
func FingerprintBytes(b []byte) Fingerprint {
	return Fingerprint(md5.Sum(b))
}

// KeysetID represents keyset ID.
type KeysetID [8]byte

func (k KeysetID) String() string {
	return hex.EncodeToString(k[:])
}

// Fingerprint represents keyset fingerprint.
type Fingerprint [md5.Size]byte

func (f Fingerprint) String() string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, len(f)*3)
	for i := 0; i < len(f); i++ {
		buf = append(buf, hex[f[i]>>4], hex[f[i]&0xf], ':')
	}
	return string(buf[:len(buf)-1])
}
