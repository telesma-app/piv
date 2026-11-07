// Package signing prepares host-side encodings for PIV signature commands.
package signing

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha1" // Register the supported hashes for crypto.Hash.New.
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
)

// DigestInfo prefixes use the DER AlgorithmIdentifier, including NULL
// parameters, followed by an OCTET STRING header. See RFC 8017, Section 9.2,
// and Go's crypto/rsa implementation for the SHA-3 identifiers.
var digestPrefixes = map[crypto.Hash][]byte{
	crypto.SHA1:       {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:     {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:     {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:     {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:     {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.SHA512_224: {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA512_256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA3_224:   {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA3_256:   {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA3_384:   {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA3_512:   {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a, 0x05, 0x00, 0x04, 0x40},
}

// ValidateDigest accepts SHA-1, SHA-224/256/384/512, SHA-512/224, SHA-512/256,
// and SHA3-224/256/384/512 with their exact digest lengths. An unhashed message
// (hash zero) and other hash identifiers are unsupported.
func ValidateDigest(hash crypto.Hash, digest []byte) error {
	if _, ok := digestPrefixes[hash]; !ok {
		return fmt.Errorf("piv: unsupported signature hash %v", hash)
	}

	if len(digest) != hash.Size() {
		return fmt.Errorf("piv: %v digest must contain %d bytes", hash, hash.Size())
	}

	return nil
}

// PKCS1v15 builds EMSA-PKCS1-v1_5 (RFC 8017, Section 9.2) for a modulus of
// keyBytes bytes. The result is the full-size input to the card's RSA primitive.
func PKCS1v15(keyBytes int, hash crypto.Hash, digest []byte) ([]byte, error) {
	if err := ValidateDigest(hash, digest); err != nil {
		return nil, err
	}

	prefix := digestPrefixes[hash]

	paddingLength := keyBytes - len(prefix) - len(digest) - 3
	if paddingLength < 8 {
		return nil, rsa.ErrMessageTooLong
	}

	em := make([]byte, keyBytes)

	em[1] = 1
	for i := range em[2 : 2+paddingLength] {
		em[2+i] = 0xff
	}

	copy(em[3+paddingLength:], prefix)
	copy(em[keyBytes-len(digest):], digest)

	return em, nil
}

// PSS builds EMSA-PSS (RFC 8017, Section 9.1.1) with emBits=modulusBits-1 and
// MGF1 using opts.Hash. SaltLength follows rsa.PSSOptions: Auto uses the maximum
// fitting length, EqualsHash uses the hash length, and positive values are exact.
// Random is used only to fill the salt; the options are not modified.
func PSS(random io.Reader, modulusBits int, digest []byte, opts *rsa.PSSOptions) ([]byte, error) {
	hashID := opts.HashFunc()
	if err := ValidateDigest(hashID, digest); err != nil {
		return nil, err
	}

	if opts.SaltLength < rsa.PSSSaltLengthEqualsHash {
		return nil, fmt.Errorf("piv: invalid PSS salt length %d", opts.SaltLength)
	}

	emBits := modulusBits - 1
	emLength := (emBits + 7) / 8
	hashLength := hashID.Size()

	maxSalt := emLength - hashLength - 2
	if maxSalt < 0 {
		return nil, rsa.ErrMessageTooLong
	}

	saltLength := opts.SaltLength
	switch saltLength {
	case rsa.PSSSaltLengthAuto:
		saltLength = maxSalt
	case rsa.PSSSaltLengthEqualsHash:
		saltLength = hashLength
	}

	if saltLength > maxSalt {
		return nil, rsa.ErrMessageTooLong
	}

	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, fmt.Errorf("piv: RSA-PSS salt: %w", err)
	}

	em := make([]byte, emLength)
	db := em[:emLength-hashLength-1]
	db[len(db)-saltLength-1] = 1
	copy(db[len(db)-saltLength:], salt)

	h := hashID.New()

	var zeros [8]byte

	_, _ = h.Write(zeros[:])
	_, _ = h.Write(digest)
	_, _ = h.Write(salt)
	encodedHash := h.Sum(em[len(db):len(db)])
	mgf1XOR(db, h, encodedHash)
	db[0] &= 0xff >> (8*emLength - emBits)
	em[emLength-1] = 0xbc

	return em, nil
}

func mgf1XOR(destination []byte, h hash.Hash, seed []byte) {
	var counter [4]byte
	for block := uint32(0); len(destination) != 0; block++ {
		binary.BigEndian.PutUint32(counter[:], block)
		h.Reset()
		_, _ = h.Write(seed)
		_, _ = h.Write(counter[:])
		mask := h.Sum(nil)

		n := min(len(destination), len(mask))
		for i := range n {
			destination[i] ^= mask[i]
		}

		destination = destination[n:]
	}
}
