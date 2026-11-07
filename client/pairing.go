package client

import (
	"context"
	"errors"

	"github.com/telesma-app/piv/protocol"
)

// VerifyPairingCode submits exactly eight ASCII decimal digits using VERIFY
// reference 98 (SP 800-73-5 Part 2, Secs. 2.4.3 and 3.2.1.3). A failed check
// clears the pairing security status and returns APDU status 6300; pairing has
// no retry counter. Over contactless, use a secure messaging transport.
func (c *Client) VerifyPairingCode(ctx context.Context, code string) error {
	var encoded [8]byte
	if len(code) != len(encoded) {
		return errors.New("piv: pairing code must contain eight ASCII digits")
	}

	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return errors.New("piv: pairing code must contain eight ASCII digits")
		}
	}

	copy(encoded[:], code)
	defer clear(encoded[:])

	return c.Verify(ctx, protocol.VerifyRequest{Reference: protocol.PairingCode, Data: encoded[:]})
}
