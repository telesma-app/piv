package sm

import (
	"bytes"
	"testing"
)

func TestCMACVectors(t *testing.T) {
	// NIST SP 800-38B, original Appendix D.3: AES-256 examples 9 through 12.
	// https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
	key := decodeHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
	message := decodeHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")

	for _, test := range []struct {
		name string
		size int
		mac  string
	}{
		{name: "empty", size: 0, mac: "028962f61b7bf89efc6b551f4667d983"},
		{name: "one block", size: 16, mac: "28a7023f452e8f82bd4bf28d8c37c35c"},
		{name: "partial block", size: 40, mac: "aaf3d8f1de5640c232f5b169b9c911e6"},
		{name: "four blocks", size: 64, mac: "e1992190549f6ed5696a2c056c315410"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := cmac(key, message[:test.size])
			if !bytes.Equal(got[:], decodeHex(t, test.mac)) {
				t.Errorf("CMAC = %x, want %s", got, test.mac)
			}
		})
	}
}

func TestAES128CMACVectors(t *testing.T) {
	// NIST SP 800-38B Appendix D.1, examples 1-4.
	key := decodeHex(t, "2b7e151628aed2a6abf7158809cf4f3c")

	message := decodeHex(t, "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	for _, test := range []struct {
		size int
		mac  string
	}{
		{size: 0, mac: "bb1d6929e95937287fa37d129b756746"},
		{size: 16, mac: "070a16b46b4d4144f79bdd9dd04a287c"},
		{size: 40, mac: "dfa66747de9ae63030ca32611497c827"},
		{size: 64, mac: "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		got := cmac(key, message[:test.size])
		if !bytes.Equal(got[:], decodeHex(t, test.mac)) {
			t.Errorf("CMAC of %d bytes = %x, want %s", test.size, got, test.mac)
		}
	}
}
