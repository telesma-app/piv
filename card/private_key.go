package card

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
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
// Supported keys are RSA-1024/2048/3072/4096, ECDSA P-256/P-384/P-521,
// Ed25519 and X25519. X25519 uses an *ecdh.PublicKey and supports ECDH only.
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
		case 4096:
			algorithm = protocol.RSA4096
		default:
			return nil, fmt.Errorf("piv: unsupported RSA key size %d", key.N.BitLen())
		}
	case *ecdsa.PublicKey:
		switch key.Curve {
		case elliptic.P256():
			algorithm = protocol.ECCP256
		case elliptic.P384():
			algorithm = protocol.ECCP384
		case elliptic.P521():
			algorithm = protocol.ECCP521
		default:
			return nil, fmt.Errorf("piv: unsupported ECDSA curve %s", key.Curve.Params().Name)
		}
	case ed25519.PublicKey:
		algorithm = protocol.Ed25519
	case *ecdh.PublicKey:
		if key.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("piv: ECDH public key requires X25519")
		}

		algorithm = protocol.X25519
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
