package sm

import (
	"bytes"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestCS2DerivationVector(t *testing.T) {
	// Independent Python hashlib.sha256(counter || Z || OtherInfo), with
	// Section 4.1.6 CS2 OtherInfo and OpenSSL AES-128-CBC CMAC confirmation.
	z := make([]byte, 32)
	public := make([]byte, 65)
	public[0] = 4
	nonce := make([]byte, 16)

	for i := range z {
		z[i] = byte(i)
	}

	for i := range public[1:] {
		public[i+1] = byte(i)
	}

	for i := range nonce {
		nonce[i] = byte(i)
	}

	host := [8]byte{0, 1, 2, 3, 4, 5, 6, 7}
	card := [8]byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7}
	keys := deriveKeys(testCipherSuite(t, protocol.CipherSuite2), z, host, card, public, nonce)
	want := sessionKeys{keySize: 16}
	copy(want.cfrm[:], decodeHex(t, "d7a8cfac260298b21ea17e1b73d39616"))
	copy(want.mac[:], decodeHex(t, "122228837f7161da05023310ebfd638b"))
	copy(want.enc[:], decodeHex(t, "8ceca9da77888c620c0b0efb9f8a46fb"))
	copy(want.rmac[:], decodeHex(t, "c3eb3516f6eff4de625d56f63c3fed67"))

	if keys != want {
		t.Fatalf("derived keys = %+v, want %+v", keys, want)
	}

	confirmation := append([]byte("KC_1_V"), card[:]...)
	confirmation = append(confirmation, host[:]...)
	confirmation = append(confirmation, public[1:]...)

	cryptogram := cmac(keys.cfrm[:keys.keySize], confirmation)
	if !bytes.Equal(cryptogram[:], decodeHex(t, "9b6671f2d4b592d7a6f7fbbfdb20767a")) {
		t.Errorf("confirmation = %x", cryptogram)
	}

	keys.clear()

	if keys != (sessionKeys{}) {
		t.Error("clear retained CS2 session keys")
	}
}

func TestCS7DerivationVector(t *testing.T) {
	// Independent oracle: Python hashlib.sha384(counter || Z || OtherInfo),
	// with the Section 4.1.6 CS7 byte string below. Confirmation was computed
	// separately using OpenSSL 3 `mac -macopt cipher:AES-256-CBC ... CMAC`.
	z := make([]byte, 48)
	public := make([]byte, 97)
	public[0] = 4
	nonce := make([]byte, 24)

	for i := range z {
		z[i] = byte(i)
	}

	for i := range public[1:] {
		public[i+1] = byte(i)
	}

	for i := range nonce {
		nonce[i] = byte(i)
	}

	host := [8]byte{0, 1, 2, 3, 4, 5, 6, 7}
	card := [8]byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7}

	keys := deriveKeys(testCipherSuite(t, protocol.CipherSuite7), z, host, card, public, nonce)
	want := decodeHex(t, "f82a1fcfba1be3297410aad16c6df8ace25dfd07795ddfb336b4886753f72867ac3e35484f09f15da5389ef3a98427131d1d5687612a0fe323684a8efe066ee0e89d0a6291321d7c9e1dac2fda8bc97fb0ee59809c6deff14a82f3dcde53230a3e26208d3fa4aabd69355110de78ddc8021354b198c9c5856a427660a9890e9a")

	got := append(keys.cfrm[:], keys.mac[:]...)
	got = append(got, keys.enc[:]...)

	got = append(got, keys.rmac[:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("derived keys = %x, want %x", got, want)
	}

	confirmation := append([]byte("KC_1_V"), card[:]...)
	confirmation = append(confirmation, host[:]...)
	confirmation = append(confirmation, public[1:]...)

	cryptogram := cmac(keys.cfrm[:], confirmation)
	if !bytes.Equal(cryptogram[:], decodeHex(t, "2943294e03721b91f11c57b98ef3a182")) {
		t.Errorf("confirmation = %x", cryptogram)
	}

	keys.clear()

	if keys != (sessionKeys{}) {
		t.Error("clear retained session keys")
	}
}
