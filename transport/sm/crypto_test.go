package sm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
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

func TestAES128EncryptionVectors(t *testing.T) {
	// Independent OpenSSL AES-128-ECB(counter), then AES-128-CBC (-nopad).
	key := decodeHex(t, "2b7e151628aed2a6abf7158809cf4f3c")

	plaintext := decodeHex(t, "000102030405060708090a0b0c0d0e0f10111213")
	for _, test := range []struct{ counter, ciphertext string }{
		{counter: "00000000000000000000000000000001", ciphertext: "0d66bb7e63a23b15adf8f8493d2bd57a6a32b661b401b12bc4e6f42e3ebd19c5"},
		{counter: "80000000000000000000000000000001", ciphertext: "176b787707b836959b569e692f07263f8072f5713d094d425130c02d8883420d"},
	} {
		counter := [16]byte(decodeHex(t, test.counter))

		ciphertext := decodeHex(t, test.ciphertext)
		if got := encrypt(key, counter, plaintext); !bytes.Equal(got, ciphertext) {
			t.Errorf("encrypt = %x, want %x", got, ciphertext)
		}

		if got, err := decrypt(key, counter, ciphertext); err != nil || !bytes.Equal(got, plaintext) {
			t.Errorf("decrypt = %x, %v, want %x", got, err, plaintext)
		}
	}
}

func TestEncryptionVectors(t *testing.T) {
	// Independently generated using OpenSSL 3 AES-256-ECB(counter) and
	// AES-256-CBC with explicit 80/00 padding, per Section 4.2.2.
	key := decodeHex(t, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")

	plaintext := decodeHex(t, "000102030405060708090a0b0c0d0e0f10111213")
	for _, test := range []struct {
		name    string
		counter string
		want    string
	}{
		{name: "command", counter: "00000000000000000000000000000001", want: "286c4e7b32ad857b60d9b45fef5f56f9ae5f48907389b042f6c12e3da00b816a"},
		{name: "response", counter: "80000000000000000000000000000001", want: "c537dfb3540ffc72ea0ed7099278db8cc0b4e3390f84add8c1211c3d7259b246"},
	} {
		t.Run(test.name, func(t *testing.T) {
			counter := [16]byte(decodeHex(t, test.counter))

			got := encrypt(key, counter, plaintext)
			if !bytes.Equal(got, decodeHex(t, test.want)) {
				t.Errorf("encrypt = %x, want %s", got, test.want)
			}

			decoded, err := decrypt(key, counter, decodeHex(t, test.want))
			if err != nil || !bytes.Equal(decoded, plaintext) {
				t.Errorf("decrypt = %x, %v, want %x", decoded, err, plaintext)
			}
		})
	}
}

func TestDecryptRejectsMalformedPadding(t *testing.T) {
	key := make([]byte, 32)
	counter := [16]byte{15: 1}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	var iv [16]byte
	block.Encrypt(iv[:], counter[:])

	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "zero padding", data: make([]byte, 16)},
		{name: "invalid marker", data: append(make([]byte, 15), 0x81)},
		{name: "padding crosses block", data: append([]byte{0x80}, make([]byte, 31)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			ciphertext := make([]byte, len(test.data))
			cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, test.data)

			got, err := decrypt(key, counter, ciphertext)
			if !errors.Is(err, ErrInvalidResponse) || got != nil {
				t.Errorf("decrypt = %x, %v, want invalid response without plaintext", got, err)
			}
		})
	}

	for _, ciphertext := range [][]byte{nil, make([]byte, 1), make([]byte, 17)} {
		if got, err := decrypt(key, counter, ciphertext); !errors.Is(err, ErrInvalidResponse) || got != nil {
			t.Errorf("decrypt malformed length %d = %x, %v", len(ciphertext), got, err)
		}
	}
}

func decodeHex(t testing.TB, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}
