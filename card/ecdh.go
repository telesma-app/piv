package card

import (
	"context"
	"crypto/ecdh"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// ECDH computes a shared secret using a P-256 or P-384 key in the key-management
// slot or a retired key-management slot (SP 800-73-5 Part 2, Appendix A.5.2).
// Peer must use the bound key's curve. The returned secret is the fixed-width,
// big-endian x coordinate, including leading zero bytes: 32 bytes for P-256 or
// 48 bytes for P-384. The caller owns it and applies the application's KDF.
// ECDH does not prove that the slot's key matches the bound public key.
//
// Authentication follows [AuthenticationSource].
func (key *PrivateKey) ECDH(
	ctx context.Context,
	peer *ecdh.PublicKey,
	authentication AuthenticationSource,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if key.reference != protocol.KeyManagement &&
		(key.reference < protocol.RetiredKey1 || key.reference > protocol.RetiredKey20) {
		return nil, fmt.Errorf("piv: ECDH requires a key-management slot")
	}

	var (
		curve ecdh.Curve
		width int
	)

	switch key.algorithm {
	case protocol.ECCP256:
		curve, width = ecdh.P256(), 32
	case protocol.ECCP384:
		curve, width = ecdh.P384(), 48
	default:
		return nil, fmt.Errorf("piv: ECDH requires a P-256 or P-384 key")
	}

	if peer.Curve() != curve {
		return nil, fmt.Errorf("piv: ECDH peer curve does not match the bound key")
	}

	var request protocol.VerifyRequest

	if authentication != nil {
		var err error

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
		Response: []byte{}, Exponentiation: peer.Bytes(),
	})
	if err != nil {
		return nil, key.device.operationError(err)
	}

	if len(response.Response) != width || response.Witness != nil || response.Challenge != nil || response.Exponentiation != nil {
		clear(response.Witness)
		clear(response.Challenge)
		clear(response.Response)
		clear(response.Exponentiation)

		return nil, fmt.Errorf("%w: invalid ECDH response", protocol.ErrInvalidResponse)
	}

	return response.Response, nil
}
