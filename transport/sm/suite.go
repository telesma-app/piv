package sm

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"

	"github.com/telesma-app/piv/protocol"
)

// cipherSuite contains the alternatives in SP 800-73-5 Part 2, Tables 18-20
// and Section 4.1.6. Record framing and AES block/MAC sizes are shared.
type cipherSuite struct {
	algorithm    protocol.Algorithm
	curve        ecdh.Curve
	signingCurve elliptic.Curve
	newHash      func() hash.Hash
	curveOID     []byte
	signatureOID asn1.ObjectIdentifier
	keySize      int
	nonceSize    int
	kdfAlgorithm byte
}

func selectCipherSuite(algorithm protocol.Algorithm) (cipherSuite, error) {
	switch algorithm {
	case protocol.CipherSuite2:
		return cipherSuite{
			algorithm: algorithm, curve: ecdh.P256(), signingCurve: elliptic.P256(),
			newHash: sha256.New, curveOID: []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7},
			signatureOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
			keySize:      16, nonceSize: 16, kdfAlgorithm: 0x09,
		}, nil
	case protocol.CipherSuite7:
		return cipherSuite{
			algorithm: algorithm, curve: ecdh.P384(), signingCurve: elliptic.P384(),
			newHash: sha512.New384, curveOID: []byte{0x2b, 0x81, 4, 0, 0x22},
			signatureOID: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3},
			keySize:      32, nonceSize: 24, kdfAlgorithm: 0x0d,
		}, nil
	default:
		return cipherSuite{}, fmt.Errorf("sm: select cipher suite 2 (27) or 7 (2E) explicitly")
	}
}
