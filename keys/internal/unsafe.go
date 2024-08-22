package internal

import (
	"unsafe"
)

func UnsafeCast[To any](from any) *To {
	iface := *(*[2]uintptr)(unsafe.Pointer(&from))
	return (*To)(unsafe.Pointer(iface[1]))
}
