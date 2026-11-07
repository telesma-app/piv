package signing

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"testing"
)

func decodeHex(t testing.TB, text string) []byte {
	t.Helper()

	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

func digestFor(t testing.TB, algorithm crypto.Hash) []byte {
	t.Helper()

	h := algorithm.New()
	_, _ = h.Write([]byte("PIV signature encoding"))

	return h.Sum(nil)
}

// This fixed public key and private exponent are Example 10 from RSA's
// PKCS #1 v2.1 pss-vect.txt, also distributed in Go's crypto/rsa/testdata.
// Only the test oracle performs the private operation in software.
func rsaVectorKey(t testing.TB) (*rsa.PublicKey, *big.Int) {
	t.Helper()
	n := new(big.Int).SetBytes(decodeHex(t,
		"a5dd867ac4cb02f90b9457d48c14a770ef991c56c39c0ec65fd11afa8937cea5"+
			"7b9be7ac73b45c0017615b82d622e318753b6027c0fd157be12f8090fee2a7ad"+
			"cd0eef759f88ba4997c7a42d58c9aa12cb99ae001fe521c13bb5431445a8d5ae"+
			"4f5e4c7e948ac227d3604071f20e577e905fbeb15dfaf06d1de5ae6253d63a6a"+
			"2120b31a5da5dabc9550600e20f27d3739e2627925fea3cc509f21dff04e6eea"+
			"4549c540d6809ff9307eede91fff58733d8385a237d6d3705a33e39190099207"+
			"0df7adf1357cf7e3700ce3667de83f17b8df1778db381dce09cb4ad058a51100"+
			"1a738198ee27cf55a13b754539906582ec8b174bd58d5d1f3d767c613721ae05"))
	d := new(big.Int).SetBytes(decodeHex(t,
		"2d2ff567b3fe74e06191b7fded6de112290c670692430d5969184047da234c96"+
			"93deed1673ed429539c969d372c04d6b47e0f5b8cee0843e5c22835dbd3b05a0"+
			"997984ae6058b11bc4907cbf67ed84fa9ae252dfb0d0cd49e618e35dfdfe59bc"+
			"a3ddd66c33cebbc77ad441aa695e13e324b518f01c60f5a85c994ad179f2a6b5"+
			"fbe93402b11767be01bf073444d6ba1dd2bca5bd074d4a5fae3531ad1303d84b"+
			"30d897318cbbba04e03c2e66de6d91f82f96ea1d4bb54a5aae102d594657f5c9"+
			"789553512b296dea29d8023196357e3e3a6e958f39e3c2344038ea604b31edc6"+
			"f0f7ff6e7181a57c92826a268f86768e96f878562fc71d85d69e448612f7048f"))

	return &rsa.PublicKey{N: n, E: 65537}, d
}

func rawRSASign(publicKey *rsa.PublicKey, d *big.Int, encoded []byte) []byte {
	message := new(big.Int).SetBytes(encoded)
	signature := new(big.Int).Exp(message, d, publicKey.N)

	return signature.FillBytes(make([]byte, publicKey.Size()))
}

func TestPKCS1v15ExactEncoding(t *testing.T) {
	digest := bytes.Repeat([]byte{0x03}, 32)
	// The independently specified 64-byte encoding has ten FF padding bytes
	// and the SHA-256 DigestInfo from RFC 8017, Section 9.2.
	want := decodeHex(t, "0001ffffffffffffffffffff003031300d060960864801650304020105000420"+
		"0303030303030303030303030303030303030303030303030303030303030303")

	encoded, err := PKCS1v15(64, crypto.SHA256, digest)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, want) {
		t.Errorf("encoding = %x, want %x", encoded, want)
	}
}

func TestPSSKnownAnswer(t *testing.T) {
	// RSA's pss-int.txt vector, reproduced in Go's
	// crypto/internal/fips140/rsa/TestEMSAPSS. The supplied message, salt, and
	// encoded output are independent of this implementation.
	message := decodeHex(t,
		"859eef2fd78aca00308bdc471193bf55bf9d78db8f8a672b484634f3c9c26e64"+
			"78ae10260fe0dd8c082e53a5293af2173cd50c6d5d354febf78b26021c25c027"+
			"12e78cd4694c9f469777e451e7f8e9e04cd3739c6bbfedae487fb55644e9ca"+
			"74ff77a53cb729802f6ed4a5ffa8ba159890fc")
	salt := decodeHex(t, "e3b5d5d002c1bce50c2b65ef88a188d83bce7e61")
	want := decodeHex(t,
		"66e4672e836ad121ba244bed6576b867d9a447c28a6e66a5b87dee7fbc7e65af"+
			"5057f86fae8984d9ba7f969ad6fe02a4d75f7445fefdd85b6d3a477c28d24b"+
			"a1e3756f792dd1dce8ca94440ecb5279ecd3183a311fc896da1cb39311af37e"+
			"a4a75e24bdbfd5c1da0de7cecdf1a896f9d8bc816d97cd7a2c43bad546fbe8"+
			"cfebc")
	h := crypto.SHA1.New()
	_, _ = h.Write(message)
	digest := h.Sum(nil)

	encoded, err := PSS(bytes.NewReader(salt), 1024, digest, &rsa.PSSOptions{Hash: crypto.SHA1, SaltLength: len(salt)})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(encoded, want) {
		t.Errorf("encoding = %x, want %x", encoded, want)
	}
}

func TestRSAEncodingsVerifyWithStandardLibrary(t *testing.T) {
	publicKey, d := rsaVectorKey(t)

	algorithms := []crypto.Hash{
		crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
		crypto.SHA512_224, crypto.SHA512_256,
		crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512,
	}
	for _, algorithm := range algorithms {
		t.Run(algorithm.String(), func(t *testing.T) {
			digest := digestFor(t, algorithm)

			encoded, err := PKCS1v15(publicKey.Size(), algorithm, digest)
			if err != nil {
				t.Fatal(err)
			}

			signature := rawRSASign(publicKey, d, encoded)
			if err := rsa.VerifyPKCS1v15(publicKey, algorithm, digest, signature); err != nil {
				t.Fatalf("PKCS1v15 verification failed: %v", err)
			}

			for _, saltLength := range []int{rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash, 1, 32} {
				opts := &rsa.PSSOptions{Hash: algorithm, SaltLength: saltLength}
				random := bytes.NewReader(bytes.Repeat([]byte{0xa5}, publicKey.Size()))

				encoded, err := PSS(random, publicKey.N.BitLen(), digest, opts)
				if err != nil {
					t.Fatal(err)
				}

				wantSaltLength := saltLength
				switch saltLength {
				case rsa.PSSSaltLengthAuto:
					wantSaltLength = publicKey.Size() - algorithm.Size() - 2
				case rsa.PSSSaltLengthEqualsHash:
					wantSaltLength = algorithm.Size()
				}

				if consumed := publicKey.Size() - random.Len(); consumed != wantSaltLength {
					t.Errorf("salt bytes consumed = %d, want %d", consumed, wantSaltLength)
				}

				if opts.SaltLength != saltLength {
					t.Error("PSS modified caller options")
				}

				signature := rawRSASign(publicKey, d, encoded)

				verifyOpts := &rsa.PSSOptions{Hash: algorithm, SaltLength: wantSaltLength}
				if err := rsa.VerifyPSS(publicKey, algorithm, digest, signature, verifyOpts); err != nil {
					t.Fatalf("PSS salt length %d verification failed: %v", saltLength, err)
				}

				signature[len(signature)-1] ^= 1
				if err := rsa.VerifyPSS(publicKey, algorithm, digest, signature, verifyOpts); err == nil {
					t.Fatal("modified PSS signature verified")
				}
			}
		})
	}
}

func TestPSSNonOctetAlignedModulus(t *testing.T) {
	digest := digestFor(t, crypto.SHA256)

	encoded, err := PSS(bytes.NewReader(make([]byte, 32)), 1025, digest, &rsa.PSSOptions{
		Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A 1025-bit modulus uses emBits=1024, so its encoded message has 128
	// bytes even though its RSA primitive input has 129 bytes.
	if len(encoded) != 128 || encoded[len(encoded)-1] != 0xbc {
		t.Errorf("PSS encoding length = %d, want 128 with trailer BC", len(encoded))
	}
}

func TestDigestValidationRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hash   crypto.Hash
		digest []byte
	}{
		{name: "unhashed", hash: 0, digest: []byte("message")},
		{name: "unknown", hash: crypto.Hash(255), digest: make([]byte, 32)},
		{name: "unsupported MD5", hash: crypto.MD5, digest: make([]byte, 16)},
		{name: "short SHA-256 digest", hash: crypto.SHA256, digest: make([]byte, 31)},
		{name: "long SHA-256 digest", hash: crypto.SHA256, digest: make([]byte, 33)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateDigest(tc.hash, tc.digest); err == nil {
				t.Fatal("expected invalid digest error")
			}

			if _, err := PKCS1v15(256, tc.hash, tc.digest); err == nil {
				t.Error("PKCS1v15 accepted invalid digest")
			}

			if _, err := PSS(bytes.NewReader(nil), 2048, tc.digest, &rsa.PSSOptions{Hash: tc.hash}); err == nil {
				t.Error("PSS accepted invalid digest")
			}
		})
	}
}

func TestRSAEncodingRejectsInsufficientSpace(t *testing.T) {
	digest := digestFor(t, crypto.SHA512)
	if _, err := PKCS1v15(93, crypto.SHA512, digest); !errors.Is(err, rsa.ErrMessageTooLong) {
		t.Errorf("PKCS1v15 = %v, want ErrMessageTooLong", err)
	}

	for _, tc := range []struct {
		name string
		bits int
		salt int
	}{
		{name: "hash does not fit", bits: 512, salt: rsa.PSSSaltLengthAuto},
		{name: "hash-size salt does not fit", bits: 1024, salt: rsa.PSSSaltLengthEqualsHash},
		{name: "explicit salt does not fit", bits: 2048, salt: 191},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PSS(bytes.NewReader(nil), tc.bits, digest, &rsa.PSSOptions{
				Hash: crypto.SHA512, SaltLength: tc.salt,
			}); !errors.Is(err, rsa.ErrMessageTooLong) {
				t.Errorf("PSS = %v, want ErrMessageTooLong", err)
			}
		})
	}
}

type failingRandom struct {
	err error
}

func (r failingRandom) Read([]byte) (int, error) {
	return 0, r.err
}

func TestPSSRejectsInvalidSaltAndPreservesEntropyError(t *testing.T) {
	digest := digestFor(t, crypto.SHA256)
	if _, err := PSS(bytes.NewReader(nil), 2048, digest, &rsa.PSSOptions{
		Hash: crypto.SHA256, SaltLength: -2,
	}); err == nil {
		t.Fatal("expected invalid negative salt length error")
	}

	cause := errors.New("entropy unavailable")
	if _, err := PSS(failingRandom{err: cause}, 2048, digest, &rsa.PSSOptions{
		Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash,
	}); !errors.Is(err, cause) {
		t.Errorf("PSS = %v, want entropy error", err)
	}

	if _, err := PSS(bytes.NewReader([]byte{1}), 2048, digest, &rsa.PSSOptions{
		Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash,
	}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("PSS = %v, want UnexpectedEOF", err)
	}
}
