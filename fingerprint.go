package quark

import (
	"crypto/md5"
)

func PublicFingerprint(p PublicKeyset) Fingerprint {
	return FingerprintOf(p.SignPublicKey().Bytes())
}

func FingerprintOf(b []byte) Fingerprint {
	return Fingerprint(md5.Sum(b))
}

type Fingerprint [md5.Size]byte

func (f Fingerprint) String() string {
	return formatFP(f[:])
}

func formatFP(fp []byte) string {
	const hex = "0123456789abcdef"
	f := make([]byte, 0, len(fp)*3)
	for i := 0; i < len(fp); i++ {
		f = append(f, hex[fp[i]>>4], hex[fp[i]&0xf], ':')
	}
	return string(f[:len(f)-1])
}
