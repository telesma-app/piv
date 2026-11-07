package decryption

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func unhex(t testing.TB, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}

func TestOAEPKnownAnswers(t *testing.T) {
	// Encoded messages obtained from the independent raw RSA operation on
	// crypto/rsa's TestDecryptOAEP Example 1.1 and Test2DecryptOAEP vectors.
	// The first vector originates in RSA's "Test vectors for RSA-OAEP".
	for _, tc := range []struct {
		name, encoded, plaintext string
		hash, mgfHash            crypto.Hash
	}{
		{
			name: "RSA example 1.1", hash: crypto.SHA1,
			encoded: "001016e93a98ac3af3a8c48fc01e87bd7000db8bdf691f90e4dbabb03f76003765f" +
				"55b7ed7a202635ea92feda9465ec40f3e0f64b8b0e444956245c5d5d068cb0b1deca8" +
				"8b2f99ae0df4e80f017c595cdba4c92f2f46f25bdbf352beb93766d24554106f42d932" +
				"6d59339ca24f392e738c703dc876e402ee16542095b77a6994",
			plaintext: "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34",
		},
		{
			name: "SHA-256 with MGF1 SHA-1", hash: crypto.SHA256, mgfHash: crypto.SHA1,
			encoded: "009ac17fa6f44947ea65961906cded63efc16111728414a4625619612e4c4930d76d8ce" +
				"73309710b8cd4f1a48e2c3e3e882e398854441c24bf49a7d0ffeb316206b4a53e6735" +
				"edd34af72e96b02c47e05080cd43b8ffc97f18078f8848138f1df92ba0d09b4e111f8a" +
				"7b26be648004d604a70730d6689a033927c1a69335d7a9",
			plaintext: "ed36908dbefc3540704ff59d6ec2ebf527ae65b0592945258cc19122",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := unhex(t, tc.encoded)

			opts := &rsa.OAEPOptions{Hash: tc.hash, MGFHash: tc.mgfHash}
			if err := ValidateOAEP(len(em), opts); err != nil {
				t.Fatal(err)
			}

			plaintext, err := OAEP(em, opts)
			if err != nil || !bytes.Equal(plaintext, unhex(t, tc.plaintext)) {
				t.Fatalf("OAEP = %x, %v", plaintext, err)
			}

			clear(em)

			if !bytes.Equal(plaintext, unhex(t, tc.plaintext)) {
				t.Fatal("plaintext aliases encoded-message storage")
			}
		})
	}
}

// maskOAEP is a test encoder with a separately accumulated MGF1 mask. It lets
// the structural tests specify invalid unmasked DB fields independently of
// the decoder's masking implementation.
func maskOAEP(seed, db []byte, mgfHash crypto.Hash) []byte {
	mask := func(input []byte, length int) []byte {
		var result []byte
		for counter := uint32(0); len(result) < length; counter++ {
			h := mgfHash.New()
			_, _ = h.Write(input)
			_, _ = h.Write(binary.BigEndian.AppendUint32(nil, counter))
			result = h.Sum(result)
		}

		return result[:length]
	}

	maskedDB := bytes.Clone(db)
	for i, b := range mask(seed, len(db)) {
		maskedDB[i] ^= b
	}

	maskedSeed := bytes.Clone(seed)
	for i, b := range mask(maskedDB, len(seed)) {
		maskedSeed[i] ^= b
	}

	return append(append([]byte{0}, maskedSeed...), maskedDB...)
}

func TestOAEPRejectsInvalidStructureWithOneError(t *testing.T) {
	label := []byte("PIV key transport")
	h := crypto.SHA256.New()
	_, _ = h.Write(label)
	db := make([]byte, 128-h.Size()-1)
	copy(db, h.Sum(nil))

	db[len(db)-1] = 1 // A valid encoding of the empty plaintext.
	seed := bytes.Repeat([]byte{0xa5}, h.Size())

	for _, tc := range []struct {
		name string
		edit func([]byte, []byte)
	}{
		{name: "label hash", edit: func(db, _ []byte) { db[0] ^= 1 }},
		{name: "nonzero padding", edit: func(db, _ []byte) { db[h.Size()] = 2 }},
		{name: "missing separator", edit: func(db, _ []byte) { db[len(db)-1] = 0 }},
		{name: "wrong header", edit: func(_, em []byte) { em[0] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changedDB := bytes.Clone(db)
			if tc.name != "wrong header" {
				tc.edit(changedDB, nil)
			}

			em := maskOAEP(seed, changedDB, crypto.SHA256)
			if tc.name == "wrong header" {
				tc.edit(nil, em)
			}

			plaintext, err := OAEP(em, &rsa.OAEPOptions{Hash: crypto.SHA256, Label: label})
			if plaintext != nil || err != rsa.ErrDecryption {
				t.Fatalf("OAEP = %x, %v; want only rsa.ErrDecryption", plaintext, err)
			}
		})
	}

	plaintext, err := OAEP(maskOAEP(seed, db, crypto.SHA256), &rsa.OAEPOptions{Hash: crypto.SHA256, Label: label})
	if err != nil || len(plaintext) != 0 {
		t.Fatalf("empty OAEP = %x, %v", plaintext, err)
	}
}

func TestValidateOAEP(t *testing.T) {
	for _, hash := range []crypto.Hash{
		crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
		crypto.SHA512_224, crypto.SHA512_256,
		crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512,
	} {
		if err := ValidateOAEP(2*hash.Size()+2, &rsa.OAEPOptions{Hash: hash, MGFHash: crypto.SHA256}); err != nil {
			t.Errorf("supported hash %v: %v", hash, err)
		}

		if err := ValidateOAEP(2*hash.Size()+1, &rsa.OAEPOptions{Hash: hash}); !errors.Is(err, rsa.ErrDecryption) {
			t.Errorf("insufficient room for %v = %v", hash, err)
		}
	}

	for _, opts := range []*rsa.OAEPOptions{
		{},
		{Hash: crypto.MD5},
		{Hash: crypto.Hash(255)},
		{Hash: crypto.SHA256, MGFHash: crypto.MD5},
		{Hash: crypto.SHA256, MGFHash: crypto.Hash(255)},
	} {
		if err := ValidateOAEP(256, opts); err == nil {
			t.Errorf("unsupported options accepted: %+v", opts)
		}
	}
}

func pkcs1Encoding(size int, message []byte) []byte {
	em := bytes.Repeat([]byte{0x5a}, size)
	em[0], em[1], em[size-len(message)-1] = 0, 2, 0
	copy(em[size-len(message):], message)

	return em
}

func TestPKCS1v15BoundariesAndOwnership(t *testing.T) {
	for _, message := range [][]byte{nil, {0}, bytes.Repeat([]byte{0xa5}, 245)} {
		size := max(11, len(message)+11)
		em := pkcs1Encoding(size, message)

		plaintext, err := PKCS1v15(em)
		if err != nil || !bytes.Equal(plaintext, message) {
			t.Fatalf("PKCS1v15 = %x, %v", plaintext, err)
		}

		clear(em)

		if !bytes.Equal(plaintext, message) {
			t.Fatal("PKCS1v15 plaintext aliases encoded message")
		}
	}
}

func TestPKCS1v15PaddingAndSessionKey(t *testing.T) {
	message := bytes.Repeat([]byte{0xa5}, 16)

	for _, tc := range []struct {
		name  string
		edit  func([]byte)
		valid bool
	}{
		{name: "valid", valid: true, edit: func([]byte) {}},
		{name: "first byte", edit: func(em []byte) { em[0] = 1 }},
		{name: "block type", edit: func(em []byte) { em[1] = 1 }},
		{name: "seven padding bytes", edit: func(em []byte) { em[9] = 0 }},
		{name: "missing separator", edit: func(em []byte) { em[len(em)-len(message)-1] = 0x5a }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := pkcs1Encoding(128, message)
			tc.edit(em)

			plaintext, err := PKCS1v15(em)
			if tc.valid {
				if err != nil || !bytes.Equal(plaintext, message) {
					t.Fatalf("PKCS1v15 = %x, %v", plaintext, err)
				}
			} else if plaintext != nil || err != rsa.ErrDecryption {
				t.Fatalf("PKCS1v15 = %x, %v", plaintext, err)
			}

			for _, size := range []int{15, 16, 17} {
				fallback := bytes.Repeat([]byte{0x42}, size)

				want := bytes.Clone(fallback)
				if tc.valid && size == len(message) {
					want = message
				}

				PKCS1v15SessionKey(em, fallback)

				if !bytes.Equal(fallback, want) {
					t.Errorf("session key length %d = %x, want %x", size, fallback, want)
				}
			}
		})
	}
}
