package quark

import (
	"crypto/md5"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/sha3"
)

// KeyFlag represents key flag.
type KeyFlag byte

// key flags.
const (
	FlagSign KeyFlag = 1 << iota
	FlagEncapsulate
	flagCertify
	Primary KeyFlag = FlagSign | flagCertify
)

// IsPrimary returns true if the key is primary.
func (f KeyFlag) IsPrimary() bool { return f&Primary == Primary }

// CanSign returns true if the key can sign.
func (f KeyFlag) CanSign() bool { return f&FlagSign != 0 }

// CanEncapsulate returns true if the key can encrypt.
func (f KeyFlag) CanEncapsulate() bool { return f&FlagEncapsulate != 0 }

// Algorithm represents algorithm as string.
type Algorithm string

// InvalidAlgorithm represents unsupported or invalid algorithm.
const InvalidAlgorithm Algorithm = "INVALID"

// Key represents de/serializable key.
type Key struct {
	KeyFlag   `msgpack:"flag"`
	Algorithm Algorithm `msgpack:"algorithm"`
	Created   int64     `msgpack:"created"`
	Expires   int64     `msgpack:"expires"`
	Key       []byte    `msgpack:"key"`
}

// id sizes.
const (
	IDSize       = md5.Size / 2 // 8
	IDStringSize = IDSize * 2   // hexed id (16)
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

// CalculateID calculates key ID.
func CalculateID(publicMaterial []byte) ID {
	sum := md5.Sum(publicMaterial)
	subtle.XORBytes(sum[:IDSize], sum[:IDSize], sum[IDSize:])
	return ID(sum[:IDSize])
}

// ID represents the key ID.
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

// fp sizes.
const (
	FPSize       = 32                      // sha3-256 output
	FPStringSize = FPSize*2 + FPSize/2 - 1 // 79
)

// CalculateFingerprint calculates key fingerprint.
func CalculateFingerprint(publicKey []byte) Fingerprint {
	return Fingerprint(sha3.Sum256(publicKey))
}

// FingerprintFromString parses string keyset fingerprint.
func FingerprintFromString(strFP string) (fp Fingerprint, ok bool) {
	if len(strFP) != FPStringSize {
		return
	}
	strFP = strings.ReplaceAll(strFP, ":", "")
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
		buf = append(buf, hex[f[i]>>4], hex[f[i]&0xf])
		i++
		buf = append(buf, hex[f[i]>>4], hex[f[i]&0xf], ':')
	}
	return string(buf[:len(buf)-1])
}
