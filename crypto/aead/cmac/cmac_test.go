package cmac_test

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"

	"github.com/karalef/quark/crypto/aead/cmac"
)

type cmacTestVector struct {
	plain, mac string
}

var cmacTestVectors = map[string][4]cmacTestVector{
	"2b7e151628aed2a6abf7158809cf4f3c": {
		{"", "bb1d6929e95937287fa37d129b756746"},
		{"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
	},
	"8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b": {
		{"", "d17ddf46adaacde531cac483de7a9367"},
		{"6bc1bee22e409f96e93d7e117393172a", "9e99a7bf31e710900662f65e617c5184"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "8a1de5be2eb31aad089a82e6ee908b0e"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "a1d5df0eed790f794d77589659f39a11"},
	},
	"603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4": {
		{"", "028962f61b7bf89efc6b551f4667d983"},
		{"6bc1bee22e409f96e93d7e117393172a", "28a7023f452e8f82bd4bf28d8c37c35c"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "aaf3d8f1de5640c232f5b169b9c911e6"},
		{"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "e1992190549f6ed5696a2c056c315410"},
	},
}

func TestCmac(t *testing.T) {
	for hexkey, vectors := range cmacTestVectors {
		key, err := hex.DecodeString(hexkey)
		if err != nil {
			t.Fatal(err)
		}
		b, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		for i, vec := range vectors {
			plain, err := hex.DecodeString(vec.plain)
			if err != nil {
				t.Fatal(err)
			}
			mac := cmac.Tag(nil, b, plain)
			expected, err := hex.DecodeString(vec.mac)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expected, mac) {
				bits := len(key) * 8
				t.Errorf("wrong mac for %d-bit key (vector %d), expected %x, got %x", bits, i+1, expected, mac)
			}
		}
	}
}

func TestCmacStream(t *testing.T) {
	for hexkey, vectors := range cmacTestVectors {
		key, err := hex.DecodeString(hexkey)
		if err != nil {
			t.Fatal(err)
		}
		b, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}
		for i, vec := range vectors {
			plain, err := hex.DecodeString(vec.plain)
			if err != nil {
				t.Fatal(err)
			}
			cmac := cmac.New(b)
			cmac.Write(plain)
			mac := cmac.Sum(nil)
			expected, err := hex.DecodeString(vec.mac)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(expected, mac) {
				bits := len(key) * 8
				t.Errorf("wrong mac for %d-bit key (vector %d), expected %x, got %x", bits, i+1, expected, mac)
				t.Fail()
			}
		}
	}
}
