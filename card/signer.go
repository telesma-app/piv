package card

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/telesma-app/piv/internal/signing"
	"github.com/telesma-app/piv/protocol"
)

// Signature generation: SP 800-73-5 Part 2, Appendix A.4.

// Sign signs using the slot's private key. RSA PKCS#1 v1.5 and ECDSA take a
// digest with crypto.Hash options; RSA-PSS takes *rsa.PSSOptions. Digest lengths
// must match the chosen SHA hash. Ed25519 takes the original message and either
// crypto.Hash(0) or empty *ed25519.Options; Ed25519ph and Ed25519ctx are unsupported.
// Random is used for PSS salt; other modes obtain any required entropy on the
// card. Input and options are borrowed for the call and must not be modified
// while it is in progress. X25519 keys cannot sign.
//
// Authentication follows [AuthenticationSource]. Input preparation precedes
// the source.
//
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
	switch key.publicKey.(type) {
	case ed25519.PublicKey:
		switch options := opts.(type) {
		case crypto.Hash:
			if options != 0 {
				return nil, fmt.Errorf("piv: Ed25519 requires an unhashed message")
			}
		case *ed25519.Options:
			if options.Hash != 0 || options.Context != "" {
				return nil, fmt.Errorf("piv: Ed25519ph and Ed25519ctx are unsupported")
			}
		default:
			return nil, fmt.Errorf("piv: unsupported Ed25519 options %T", opts)
		}

		if len(digest) == 0 {
			return []byte{}, nil
		}

		return digest, nil
	case *ecdh.PublicKey:
		return nil, fmt.Errorf("piv: X25519 keys cannot sign")
	}

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

		// P-521 accepts the original SHA digest, whose length is at most 64
		// bytes. Preserve that length for its non-byte-aligned curve order.
		if key.algorithm == protocol.ECCP521 {
			return digest, nil
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
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey, digest, signature) {
			return fmt.Errorf("invalid Ed25519 signature")
		}

		return nil
	default:
		panic("unsupported bound public key")
	}
}

type signer struct {
	key            *PrivateKey
	ctx            context.Context
	authentication AuthenticationSource
}

var _ crypto.Signer = (*signer)(nil)

// Signer adapts the key to crypto.Signer using ctx for every signature.
// Create it for the lifetime of the request. Cancellation follows the transport's
// contract; authentication follows [AuthenticationSource]. The adapter borrows
// the key and does not close its Device.
func (key *PrivateKey) Signer(ctx context.Context, authentication AuthenticationSource) crypto.Signer {
	return &signer{key: key, ctx: ctx, authentication: authentication}
}

func (s *signer) Public() crypto.PublicKey {
	return s.key.Public()
}

func (s *signer) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return s.key.Sign(s.ctx, random, digest, opts, s.authentication)
}
