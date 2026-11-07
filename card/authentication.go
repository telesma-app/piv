package card

import (
	"context"

	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// AuthenticationSource supplies a VERIFY request for one private-key operation.
// It is called before the operation gate and may prompt the user or call Device
// methods. Concurrent operations may call the source concurrently. A nil source
// explicitly requests the operation without VERIFY.
//
// On success, ownership of the request's Data passes to the operation, which
// clears it before returning. The source must return data that the operation may
// clear and must not access that data until the operation returns. On error, the
// source retains ownership of any returned data. The key and its adapters do not
// retain the request.
type AuthenticationSource func(context.Context) (protocol.VerifyRequest, error)

// PINAuthentication obtains and encodes a standard six-to-eight-digit PIV PIN
// for the explicitly selected reference, typically ApplicationPIN or GlobalPIN.
// It calls source for every operation. The PIN is not retained; its encoded
// buffer is owned and cleared by that operation according to AuthenticationSource's
// contract.
func PINAuthentication(
	reference protocol.KeyReference,
	source func(context.Context) (string, error),
) AuthenticationSource {
	return func(ctx context.Context) (protocol.VerifyRequest, error) {
		pin, err := source(ctx)
		if err != nil {
			return protocol.VerifyRequest{}, err
		}

		encoded, err := client.EncodePIN(pin)
		if err != nil {
			return protocol.VerifyRequest{}, err
		}

		return protocol.VerifyRequest{Reference: reference, Data: encoded[:]}, nil
	}
}
