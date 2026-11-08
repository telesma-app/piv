package sm

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"
)

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
