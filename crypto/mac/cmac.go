package mac

import "github.com/karalef/quark/crypto/block"

func init() {
	Register(AES128CMAC)
	Register(AES192CMAC)
	Register(AES256CMAC)
}

// AES-CMAC
var (
	AES128CMAC = New("AES128_CMAC", block.AES128.KeySize(), 0, block.CMACBlockSize, block.CMACBlockSize, newAESCMAC)
	AES192CMAC = New("AES192_CMAC", block.AES192.KeySize(), 0, block.CMACBlockSize, block.CMACBlockSize, newAESCMAC)
	AES256CMAC = New("AES256_CMAC", block.AES256.KeySize(), 0, block.CMACBlockSize, block.CMACBlockSize, newAESCMAC)
)

func newAESCMAC(key []byte) State {
	var sch block.Scheme
	switch len(key) {
	case 16:
		sch = block.AES128
	case 24:
		sch = block.AES192
	case 32:
		sch = block.AES256
	default:
		panic("never happens")
	}
	return cmac{block.NewCMAC(sch.New(key))}
}

type cmac struct{ *block.CMAC }

func (cmac) Size() int                     { return block.CMACBlockSize }
func (cmac) BlockSize() int                { return block.CMACBlockSize }
func (c cmac) Tag(dst []byte) []byte       { return c.Sum(dst) }
func (c cmac) Write(p []byte) (int, error) { c.CMAC.Write(p); return len(p), nil }
