// Package decryption decodes host-side RSA encodings returned by PIV cards.
package decryption

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha1" // Register the supported hashes for crypto.Hash.New.
	_ "crypto/sha256"
	_ "crypto/sha3"
	_ "crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"hash"
)

// ValidateOAEP checks the supported options and encoded-message size before a
// private-key operation. Hash and MGFHash accept SHA-1, SHA-2, and SHA-3 hashes;
// a zero MGFHash uses Hash. The options and their label remain borrowed.
func ValidateOAEP(keyBytes int, opts *rsa.OAEPOptions) error {
	if err := validateHash(opts.Hash); err != nil {
		return err
	}

	if opts.MGFHash != 0 {
		if err := validateHash(opts.MGFHash); err != nil {
			return err
		}
	}

	if keyBytes < 2*opts.Hash.Size()+2 {
		return rsa.ErrDecryption
	}

	return nil
}

func validateHash(id crypto.Hash) error {
	switch id {
	case crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512,
		crypto.SHA512_224, crypto.SHA512_256,
		crypto.SHA3_224, crypto.SHA3_256, crypto.SHA3_384, crypto.SHA3_512:
		return nil
	default:
		return fmt.Errorf("piv: unsupported RSA OAEP hash %v", id)
	}
}

// OAEP decodes RSAES-OAEP (RFC 8017, Section 7.1.2). ValidateOAEP must have
// succeeded for len(em). It mutates the owned encoded message and returns a
// separate plaintext so the caller can clear all encoded-message storage.
func OAEP(em []byte, opts *rsa.OAEPOptions) ([]byte, error) {
	h := opts.Hash.New()
	_, _ = h.Write(opts.Label)
	labelHash := h.Sum(nil)

	mgfHashID := opts.MGFHash
	if mgfHashID == 0 {
		mgfHashID = opts.Hash
	}

	mgfHash := mgfHashID.New()
	seed := em[1 : h.Size()+1]
	db := em[h.Size()+1:]
	mgf1XOR(seed, mgfHash, db)
	mgf1XOR(db, mgfHash, seed)

	valid := subtle.ConstantTimeByteEq(em[0], 0) & subtle.ConstantTimeCompare(db[:h.Size()], labelHash)
	looking, index, invalid := 1, 0, 0
	rest := db[h.Size():]

	for i, b := range rest {
		isZero := subtle.ConstantTimeByteEq(b, 0)
		isOne := subtle.ConstantTimeByteEq(b, 1)
		index = subtle.ConstantTimeSelect(looking&isOne, i, index)
		invalid |= looking & (1 ^ isZero) & (1 ^ isOne)
		looking &= 1 ^ isOne
	}

	if valid&(1^looking)&(1^invalid) != 1 {
		return nil, rsa.ErrDecryption
	}

	return bytes.Clone(rest[index+1:]), nil
}

// PKCS1v15 decodes RSAES-PKCS1-v1_5 (RFC 8017, Section 7.2.2). The encoded
// message must contain at least 11 bytes. The returned plaintext owns separate
// storage so the caller can clear the complete encoded message.
//
// A padding error discloses validity. This legacy mode requires a protocol that
// prevents an attacker from observing a padding oracle.
func PKCS1v15(em []byte) ([]byte, error) {
	valid, index := pkcs1v15(em)
	if valid != 1 {
		return nil, rsa.ErrDecryption
	}

	return bytes.Clone(em[index:]), nil
}

// PKCS1v15SessionKey replaces the prefilled random destination only when the
// padding and plaintext length are valid. Destination must be at most len(em)-11
// bytes long. Both alternatives use the same fixed-length memory accesses and
// expose no padding-validity result. The surrounding protocol must preserve
// that indistinguishability when it uses the key.
func PKCS1v15SessionKey(em, destination []byte) {
	valid, index := pkcs1v15(em)
	valid &= subtle.ConstantTimeEq(int32(len(em)-index), int32(len(destination)))
	subtle.ConstantTimeCopy(valid, destination, em[len(em)-len(destination):])
}

func pkcs1v15(em []byte) (valid, index int) {
	valid = subtle.ConstantTimeByteEq(em[0], 0) & subtle.ConstantTimeByteEq(em[1], 2)
	looking := 1

	for i := 2; i < len(em); i++ {
		isZero := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(looking&isZero, i, index)
		looking &= 1 ^ isZero
	}

	valid &= (1 ^ looking) & subtle.ConstantTimeLessOrEq(10, index)
	index = subtle.ConstantTimeSelect(valid, index+1, 0)

	return valid, index
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

		clear(mask)

		destination = destination[n:]
	}
}
