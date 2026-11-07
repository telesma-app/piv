package card

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/telesma-app/piv/internal/signing"
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

// Sign signs a digest using the slot's private key. Options must be crypto.Hash
// for RSA PKCS#1 v1.5 or ECDSA, or *rsa.PSSOptions for RSA-PSS. Digest lengths must
// match the chosen SHA hash. Random is used for PSS salt; other modes obtain any
// required entropy on the card. Digest and options are borrowed for the call
// and must not be modified while it is in progress.
//
// Input preparation and the optional authentication source precede the operation
// gate. The supplied VERIFY request and GENERAL AUTHENTICATE then run as one
// workflow. Reference and encoded data are sent unchanged, including Global PIN
// or OCC data. The source is called for every signature; no authentication status
// is cached and no failed command is retried. A nil source sends no VERIFY.
// On a successful source return, Sign takes ownership of its Data and clears it
// before returning, including when waiting for the operation is canceled.
//
// Sign preserves a completed signature after concurrent context cancellation.
// An invalid response or a signature that does not match Public returns an error
// matching protocol.ErrInvalidResponse and no signature.
func (key *PrivateKey) Sign(
	ctx context.Context,
	random io.Reader,
	digest []byte,
	opts crypto.SignerOpts,
	authentication AuthenticationSource,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	input, err := key.prepare(random, digest, opts)
	if err != nil {
		return nil, err
	}

	var request protocol.VerifyRequest

	if authentication != nil {
		request, err = authentication(ctx)
		if err != nil {
			return nil, err
		}
		defer clear(request.Data)
	}

	if err := key.device.lock(ctx); err != nil {
		return nil, err
	}
	defer key.device.unlock()

	if authentication != nil {
		if err := key.device.client.Verify(ctx, request); err != nil {
			return nil, key.device.operationError(err)
		}
	}

	response, err := key.device.client.GeneralAuthenticate(ctx, key.algorithm, key.reference, protocol.DynamicAuthentication{
		Challenge: input, Response: []byte{},
	})
	if err != nil {
		return nil, key.device.operationError(err)
	}

	if response.Response == nil || response.Witness != nil || response.Challenge != nil || response.Exponentiation != nil {
		return nil, fmt.Errorf("%w: invalid signing response", protocol.ErrInvalidResponse)
	}

	if err := key.verify(digest, response.Response, opts); err != nil {
		return nil, fmt.Errorf("%w: signature does not match bound public key: %v", protocol.ErrInvalidResponse, err)
	}

	return response.Response, nil
}

func (key *PrivateKey) prepare(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := opts.HashFunc()

	switch options := opts.(type) {
	case crypto.Hash:
	case *rsa.PSSOptions:
		publicKey, ok := key.publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("piv: RSA-PSS options require an RSA key")
		}

		return signing.PSS(random, publicKey.N.BitLen(), digest, options)
	default:
		return nil, fmt.Errorf("piv: unsupported signature options %T", opts)
	}

	switch publicKey := key.publicKey.(type) {
	case *rsa.PublicKey:
		return signing.PKCS1v15(publicKey.Size(), hash, digest)
	case *ecdsa.PublicKey:
		if err := signing.ValidateDigest(hash, digest); err != nil {
			return nil, err
		}

		// PIV cards such as YubiKey require exactly the curve-order width.
		// P-256 and P-384 have byte-aligned orders: truncate long digests on
		// the right and left-pad short digests to preserve their integer value.
		width := publicKey.Curve.Params().BitSize / 8
		if len(digest) >= width {
			return digest[:width], nil
		}

		input := make([]byte, width)
		copy(input[width-len(digest):], digest)

		return input, nil
	default:
		panic("unsupported bound public key")
	}
}

func (key *PrivateKey) verify(digest, signature []byte, opts crypto.SignerOpts) error {
	switch publicKey := key.publicKey.(type) {
	case *rsa.PublicKey:
		if options, ok := opts.(*rsa.PSSOptions); ok {
			saltLength := options.SaltLength
			if saltLength == rsa.PSSSaltLengthAuto {
				// VerifyPSS's Auto accepts any salt; signing Auto requested the
				// maximum length, so verify that exact length instead.
				saltLength = (publicKey.N.BitLen()-1+7)/8 - opts.HashFunc().Size() - 2
			}

			return rsa.VerifyPSS(publicKey, opts.HashFunc(), digest, signature, &rsa.PSSOptions{
				Hash: opts.HashFunc(), SaltLength: saltLength,
			})
		}

		return rsa.VerifyPKCS1v15(publicKey, opts.HashFunc(), digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey, digest, signature) {
			return fmt.Errorf("invalid ECDSA signature")
		}

		return nil
	default:
		panic("unsupported bound public key")
	}
}
