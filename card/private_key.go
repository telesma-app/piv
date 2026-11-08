package card

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// PrivateKey binds a selected card and slot to its corresponding public key.
// It borrows the Device and public key; neither is copied or owned by the key.
// Do not mutate the public key while bound. Create a new binding after replacing
// the slot's key. Every returned signature is verified against this public key.
// Decryption and ECDH do not prove that the slot still holds the bound key.
type PrivateKey struct {
	device    *Device
	reference protocol.KeyReference
	publicKey crypto.PublicKey
	algorithm protocol.Algorithm
}

// PrivateKey binds an existing slot and its known public key without I/O. Public
// keys returned by GenerateAsymmetricKeyPair or read from a matching certificate
// are suitable.
// Supported keys are RSA-1024/2048/3072 and ECDSA P-256/P-384.
func (d *Device) PrivateKey(reference protocol.KeyReference, publicKey crypto.PublicKey) (*PrivateKey, error) {
	if _, err := protocol.CertificateObject(reference); err != nil {
		return nil, err
	}

	var algorithm protocol.Algorithm

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		switch key.N.BitLen() {
		case 1024:
			algorithm = protocol.RSA1024
		case 2048:
			algorithm = protocol.RSA2048
		case 3072:
			algorithm = protocol.RSA3072
		default:
			return nil, fmt.Errorf("piv: unsupported RSA key size %d", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			algorithm = protocol.ECCP256
		case elliptic.P384():
			algorithm = protocol.ECCP384
		default:
			return nil, fmt.Errorf("piv: unsupported ECDSA curve %s", key.Curve.Params().Name)
		}
	default:
		return nil, fmt.Errorf("piv: unsupported public key type %T", publicKey)
	}

	return &PrivateKey{
		device: d, reference: reference, publicKey: publicKey, algorithm: algorithm,
	}, nil
}

// Public returns the bound public key without I/O or copying.
func (key *PrivateKey) Public() crypto.PublicKey {
	return key.publicKey
}
