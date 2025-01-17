package crypto

import (
	stdbin "encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/karalef/quark/crypto/hash"
	"github.com/karalef/quark/pack/binary"
	"github.com/karalef/quark/pkg/crockford"
)

// id sizes.
const (
	IDSize        = 8                                     // 8; last 8 bytes of fingerprint
	IDStringSize  = IDSize/5*8 + (IDSize%5*8+4)/5         // 13; base32 encoded
	FPSize        = 32                                    // 32; sha3-256 output
	FPRegularSize = FPSize/5*8 + (FPSize%5*8+4)/5         // 52; base32 encoded
	FPStringSize  = FPRegularSize + (FPRegularSize/4-1)*2 // 76; base32 encoded and parted with "::"
)

// IDFromString parses encoded key ID.
// It returns false if the string is not a valid key ID.
func IDFromString(strID string) (id ID, ok bool) {
	if len(strID) != IDStringSize {
		return
	}
	_, err := crockford.Upper.Decode(id[:], []byte(strID))
	return id, err == nil
}

// IDFromUint converts uint64 to ID.
func IDFromUint(uintID uint64) (id ID) {
	stdbin.LittleEndian.PutUint64(id[:], uintID)
	return
}

// ID represents the key ID.
type ID [IDSize]byte

// IsEmpty returns true if ID is empty.
func (id ID) IsEmpty() bool { return id == ID{} }

// Bytes returns key ID as bytes.
func (id ID) Bytes() []byte { return id[:] }

func (id ID) String() string {
	return crockford.Upper.EncodeToString(id[:])
}

// Uint returns key ID as uint64 in little endian order.
func (id ID) Uint() uint64 {
	return stdbin.LittleEndian.Uint64(id[:])
}

// EncodeMsgpack implements binary.CustomEncoder.
// Replaces the the msgpack array encoding with bytes encoding
// that is more compact in case where id is empty.
func (id ID) EncodeMsgpack(enc *binary.Encoder) error {
	if id.IsEmpty() {
		return enc.EncodeNil()
	}
	return enc.EncodeBytes(id[:])
}

// DecodeMsgpack implements binary.CustomDecoder.
// Replaces the the msgpack array encoding with bytes encoding
// that is more compact in case where id is empty.
func (id *ID) DecodeMsgpack(dec *binary.Decoder) error {
	b, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	if len(b) != IDSize {
		return errors.New("invalid ID size")
	}
	*id = ID(b)
	return nil
}

// FingerprintFromRegular parses the key fingerprint in regular format.
func FingerprintFromRegular(strFP string) (fp Fingerprint, ok bool) {
	if len(strFP) != FPRegularSize {
		return
	}
	_, err := crockford.Upper.Decode(fp[:], []byte(strFP))
	return fp, err == nil
}

// FingerprintFromString parses string key fingerprint without format check.
func FingerprintFromString(strFP string) (fp Fingerprint, ok bool) {
	if len(strFP) != FPStringSize {
		return
	}
	return FingerprintFromRegular(strings.ReplaceAll(strFP, "::", ""))
}

// ParseFingerprint parses the key fingerprint with format check.
func ParseFingerprint(strFP string) (fp Fingerprint, ok bool) {
	if len(strFP) != FPStringSize {
		return fp, false
	}

	const (
		partLen   = 4
		mustParts = FPRegularSize / partLen
	)

	parts := strings.SplitN(strFP, "::", mustParts)
	if len(parts) != mustParts {
		return fp, false
	}

	for i := 0; i < mustParts; i++ {
		if len(parts[i]) != partLen {
			return fp, false
		}
	}

	regular := strings.Join(parts, "")
	return FingerprintFromRegular(regular)
}

// Fingerprint represents the key fingerprint.
type Fingerprint [FPSize]byte

// IsEmpty returns true if fingerprint is empty.
func (f Fingerprint) IsEmpty() bool { return f == Fingerprint{} }

// ID calculates ID from fingerprint.
func (f Fingerprint) ID() ID { return ID(f[FPSize-IDSize:]) }

// Bytes returns fingerprint as bytes.
func (f Fingerprint) Bytes() []byte { return f[:] }

// String returns fingerprint as string with splitted parts by 4 chars.
func (f Fingerprint) String() string {
	reg := f.regular()
	buf := make([]byte, 0, FPRegularSize+FPRegularSize/4*2)
	for i := 0; i < FPRegularSize; i += 4 {
		buf = append(buf, reg[i:i+4]...)
		buf = append(buf, ':', ':')
	}
	return string(buf[:len(buf)-2])
}

func (f Fingerprint) regular() [FPRegularSize]byte {
	var enc [FPRegularSize]byte
	crockford.Upper.Encode(enc[:], f[:])
	return enc
}

// RegularString returns a regular string version of the fingerprint.
func (f Fingerprint) RegularString() string {
	reg := f.regular()
	return string(reg[:])
}

// EncodeMsgpack implements binary.CustomEncoder.
// Replaces the the msgpack array encoding with bytes encoding
// that is more compact in case where fingerprint is empty.
func (f Fingerprint) EncodeMsgpack(enc *binary.Encoder) error {
	if f.IsEmpty() {
		return enc.EncodeBytes(nil)
	}
	return enc.EncodeBytes(f[:])
}

// DecodeMsgpack implements binary.CustomDecoder.
// Replaces the the msgpack array encoding with bytes encoding
// that is more compact in case where fingerprint is empty.
func (f *Fingerprint) DecodeMsgpack(dec *binary.Decoder) error {
	b, err := dec.DecodeBytes()
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if len(b) != FPSize {
		return errors.New("invalid fingerprint size")
	}
	*f = Fingerprint(b)
	return nil
}

// CalculateFingerprint calculates the fingerprint of the given scheme and public key.
func CalculateFingerprint(scheme string, publicKey []byte) (fp Fingerprint) {
	sha3 := hash.SHA3.New()
	sha3.Write([]byte(strings.ToUpper(scheme)))
	sha3.Write([]byte{':'})
	sha3.Write(publicKey)
	sha3.Sum(fp[:0])
	return
}

// FingerprintFunc calculates the fingerprint using writing function.
func FingerprintFunc(writer func(io.Writer)) (fp Fingerprint) {
	sha3 := hash.SHA3.New()
	writer(sha3)
	sha3.Sum(fp[:0])
	return
}
