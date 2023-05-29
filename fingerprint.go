package quark

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/karalef/quark/kem"
	"github.com/karalef/quark/sign"
)

// id and fingerprint sizes.
const (
	FPSize       = md5.Size     // 16
	FPStringSize = FPSize*3 - 1 // 47

	IDSize       = FPSize / 2 // 8
	IDStringSize = IDSize * 2 // hexed id (16)
)

// IDFromString parses hexed keyset ID.
// It returns false if the string is not a valid keyset ID.
func IDFromString(strID string) (id ID, ok bool) {
	if len(strID) != IDStringSize {
		return
	}
	_, err := hex.Decode(id[:], []byte(strID))
	return id, err == nil
}

// IDFromUint converts uint64 to ID.
func IDFromUint(uintID uint64) (id ID) {
	binary.LittleEndian.PutUint64(id[:], uintID)
	return
}

// ID represents keyset ID.
type ID [IDSize]byte

// IsEmpty returns true if ID is empty.
func (id ID) IsEmpty() bool {
	return id == ID{}
}

func (id ID) String() string {
	return hex.EncodeToString(id[:])
}

// Uint returns keyset ID as uint64 in little endian order.
func (id ID) Uint() uint64 {
	return binary.LittleEndian.Uint64(id[:])
}

func calculateFingerprint(sign sign.PublicKey, kem kem.PublicKey) Fingerprint {
	md5 := md5.New()
	md5.Write(sign.Bytes())
	md5.Write(kem.Bytes())
	return Fingerprint(md5.Sum(nil))
}

// FingerprintFromString parses string keyset fingerprint.
func FingerprintFromString(strFP string) (fp Fingerprint, ok bool) {
	if len(strFP) != FPStringSize {
		return
	}
	strings.ReplaceAll(strFP, ":", "")
	_, err := hex.Decode(fp[:], []byte(strFP))
	return fp, err == nil
}

// Fingerprint represents keyset fingerprint.
type Fingerprint [FPSize]byte

// IsEmpty returns true if fingerprint is empty.
func (f Fingerprint) IsEmpty() bool {
	return f == Fingerprint{}
}

// ID calculates keyset ID from fingerprint.
func (f Fingerprint) ID() ID {
	return ID(f[:IDSize])
}

func (f Fingerprint) String() string {
	const hex = "0123456789abcdef"
	buf := make([]byte, 0, FPStringSize+1)
	for i := 0; i < len(f); i++ {
		buf = append(buf, hex[f[i]>>4], hex[f[i]&0xf], ':')
	}
	return string(buf[:len(buf)-1])
}
