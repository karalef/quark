package subkey

import "errors"

// Usage defines the subkey usage.
type Usage uint8

// Usage flags.
const (
	UsageSign = Usage(1 << iota)
	UsageEncrypt
	UsageCertify
	usageMax

	UsageNone = Usage(0)
)

// Has returns true if the usage contains the specified usage.
func (u Usage) Has(usage Usage) bool { return (u & usage) != 0 }

// Add adds the specified usage to the usage and returns the result.
func (u Usage) Add(usage Usage) Usage { return u | usage }

// Remove removes the specified usage from the usage and returns the result.
func (u Usage) Remove(usage Usage) Usage { return u &^ usage }

var usageToByte = map[Usage]byte{
	UsageSign:    'S',
	UsageEncrypt: 'E',
	UsageCertify: 'C',
}

// String returns the string representation of the usage.
func (u Usage) String() string {
	if u == UsageNone {
		return ""
	}
	var s [3]byte
	i := 0
	for u := UsageSign; u < usageMax; u <<= 1 {
		if u.Has(u) {
			s[i] = usageToByte[u]
			i++
		}
	}
	return string(s[:i])
}

// ErrInvalidUsage is returned when the usage is invalid.
var ErrInvalidUsage = errors.New("invalid usage")
