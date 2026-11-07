package card

import (
	"context"

	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// AuthenticationSource supplies an encoded VERIFY request for one operation.
// It is called for each operation before the gate and may prompt the user or
// call Device methods. Concurrent operations may call it concurrently. The
// request is sent unchanged; VERIFY and the card command run under one gate.
// A nil source skips VERIFY.
//
// On success, ownership of the request's Data passes to the operation, which
// clears it before returning, including after cancellation while waiting for the
// gate. The source must supply clearable data and must not access it during the
// operation. On error, the source retains ownership of any returned data.
type AuthenticationSource func(context.Context) (protocol.VerifyRequest, error)

// PINAuthentication obtains and encodes a standard six-to-eight-digit PIV PIN
// for the explicitly selected reference, typically ApplicationPIN or GlobalPIN.
// The PIN is not retained; the encoded buffer follows [AuthenticationSource].
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
