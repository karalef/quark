package crockford

import (
	"encoding/base32"
)

// Base32 alphabets
const (
	LowercaseAlphabet = "0123456789abcdefghjkmnpqrstvwxyz"
	UppercaseAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

type encoding struct {
	base32.Encoding
	upper bool
}

func (enc *encoding) Decode(dst []byte, src []byte) (n int, err error) {
	norm := normalize(make([]byte, 0, len(src)), src, enc.upper)
	return enc.Encoding.Decode(dst, norm)
}

func (enc *encoding) DecodeNoBuf(dst []byte, src []byte) (n int, err error) {
	norm := normalize(src[:0], src, enc.upper)
	return enc.Encoding.Decode(dst, norm)
}

func (enc *encoding) DecodeString(s string) ([]byte, error) {
	norm := normalize(make([]byte, 0, len(s)), []byte(s), enc.upper)
	return enc.Encoding.DecodeString(string(norm))
}

// encodings
var (
	Lower = &encoding{*base32.NewEncoding(LowercaseAlphabet).WithPadding(base32.NoPadding), false}
	Upper = &encoding{*base32.NewEncoding(UppercaseAlphabet).WithPadding(base32.NoPadding), true}
)

func normalize(dst, src []byte, upper bool) []byte {
	f := normLower
	if upper {
		f = normUpper
	}
	for _, c := range src {
		if r := f(c); r != 0 {
			dst = append(dst, r)
		}
	}
	return dst
}

func normUpper(c byte) byte {
	switch c {
	case '0', 'O', 'o':
		return '0'
	case '1', 'I', 'i', 'L', 'l':
		return '1'
	case '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z', '*', '~', '$', '=', 'U':
		return c
	case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z', 'u':
		return c + 'A' - 'a'
	}
	return 0
}

func normLower(c byte) byte {
	switch c {
	case '0', 'O', 'o':
		return '0'
	case '1', 'I', 'i', 'L', 'l':
		return '1'
	case '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z', '*', '~', '$', '=', 'u':
		return c
	case 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Y', 'Z', 'U':
		return c + 'a' - 'A'
	}
	return 0
}
