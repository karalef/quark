// package lfsr implements linear feedback shift register based pseudo random number generator.
package lfsr

import (
	"encoding/binary"
)

// LFSR represents a linear feedback shift register based pseudo random number generator.
type LFSR[T unsigned] interface {
	Bytes
	Next() T
}

// Bytes represents a lfsr based pseudo random generator.
type Bytes interface {
	// NextBytes returns the next pseudo random bytes.
	// Returns false if the sequence has completed.
	// Input length must be equal or greater than bits of lfsr.
	NextBytes([]byte) bool
}

type unsigned interface {
	uint8 | uint16 | uint32 | uint64
}

// New8 returns a 8-bit lfsr initialized with the specified seed.
func New8(seed uint8) *Lfsr8 { return &Lfsr8{seed, seed} }

var _ LFSR[uint8] = (*Lfsr8)(nil)

// Lfsr8 implements an 8-bit lfsr.
type Lfsr8 struct {
	state, seed uint8
}

// Next returns the next pseudo random number.
// Returns zero if the sequence has completed.
func (l *Lfsr8) Next() uint8 {
	s := l.state
	b := (s >> 0) ^ (s >> 2) ^ (s >> 3) ^ (s >> 4)
	l.state = (s >> 1) | (b << 7)
	if l.state == l.seed {
		return 0
	}
	return l.state
}

// NextBytes returns the next pseudo random bytes.
// Returns false if the sequence has completed.
func (l *Lfsr8) NextBytes(b []byte) bool {
	v := l.Next()
	if v == 0 {
		return false
	}
	b[0] = v
	return true
}

// New16 returns a 16-bit lfsr initialized with the specified seed.
func New16(seed uint16) *Lfsr16 { return &Lfsr16{seed, seed} }

var _ LFSR[uint16] = (*Lfsr16)(nil)

// Lfsr16 represents a 16-bit lfsr.
type Lfsr16 struct {
	state, seed uint16
}

// Next returns the next pseudo random number.
// Returns zero if the sequence has completed.
func (l *Lfsr16) Next() uint16 {
	s := l.state
	b := (s >> 0) ^ (s >> 2) ^ (s >> 3) ^ (s >> 5)
	l.state = (s >> 1) | (b << 15)
	if l.state == l.seed {
		return 0
	}
	return l.state
}

// NextBytes returns the next pseudo random bytes.
// Returns false if the sequence has completed.
func (l *Lfsr16) NextBytes(b []byte) bool {
	v := l.Next()
	if v == 0 {
		return false
	}
	binary.BigEndian.PutUint16(b, v)
	return true
}

// New32 returns a 32-bit lfsr initialized with the specified seed.
func New32(seed uint32) *Lfsr32 { return &Lfsr32{seed, seed} }

var _ LFSR[uint32] = (*Lfsr32)(nil)

// Lfsr32 represents a 32-bit lfsr.
type Lfsr32 struct {
	state, seed uint32
}

// Next returns the next pseudo random number.
// Returns zero if the sequence has completed.
func (l *Lfsr32) Next() uint32 {
	s := l.state
	b := (s >> 0) ^ (s >> 2) ^ (s >> 6) ^ (s >> 7)
	l.state = (s >> 1) | (b << 31)
	if l.state == l.seed {
		return 0
	}
	return l.state
}

// NextBytes returns the next pseudo random bytes.
// Returns false if the sequence has completed.
func (l *Lfsr32) NextBytes(b []byte) bool {
	v := l.Next()
	if v == 0 {
		return false
	}
	binary.BigEndian.PutUint32(b, v)
	return true
}

// New64 returns a 64-bit lfsr initialized with the specified seed.
func New64(seed uint64) *Lfsr64 { return &Lfsr64{seed, seed} }

var _ LFSR[uint64] = (*Lfsr64)(nil)

// Lfsr64 represents a 64-bit lfsr.
type Lfsr64 struct {
	state, seed uint64
}

// Next returns the next pseudo random number.
// Returns zero if the sequence has completed.
func (l *Lfsr64) Next() uint64 {
	s := l.state
	b := (s >> 0) ^ (s >> 1) ^ (s >> 3) ^ (s >> 4)
	l.state = (s >> 1) | (b << 63)
	if l.state == l.seed {
		return 0
	}
	return l.state
}

// NextBytes returns the next pseudo random bytes.
// Returns false if the sequence has completed.
func (l *Lfsr64) NextBytes(b []byte) bool {
	v := l.Next()
	if v == 0 {
		return false
	}
	binary.BigEndian.PutUint64(b, v)
	return true
}
