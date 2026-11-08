package client

import (
	"context"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// ReferenceStatus reports the result of an empty VERIFY. Retries is meaningful
// when Verified is false and is taken from an explicit 63Cx response. A zero
// retry count means the reference is blocked.
type ReferenceStatus struct {
	Verified bool
	Retries  int
}

// ReferenceStatus queries a reference's security status without submitting
// authentication data or consuming a retry. Card policies may restrict the
// command over contactless connections. Status 6983 is returned as an APDUError
// because it does not supply a retry count.
func (c *Client) ReferenceStatus(ctx context.Context, reference protocol.KeyReference) (ReferenceStatus, error) {
	err := c.Verify(ctx, protocol.VerifyRequest{Reference: reference})
	if err == nil {
		return ReferenceStatus{Verified: true}, nil
	}

	if referenceError, ok := err.(*ReferenceDataError); ok {
		return ReferenceStatus{Retries: referenceError.Retries}, nil
	}

	return ReferenceStatus{}, err
}

// ResetSecurityStatus clears a reference's security status using VERIFY P1=FF.
// It does not submit reference data.
func (c *Client) ResetSecurityStatus(ctx context.Context, reference protocol.KeyReference) error {
	return c.Verify(ctx, protocol.VerifyRequest{Reference: reference, ResetSecurityStatus: true})
}

// VerifyPIN verifies the application PIN using the standard PIV encoding.
// An incorrect PIN consumes a retry.
func (c *Client) VerifyPIN(ctx context.Context, pin string) error {
	encoded, err := EncodePIN(pin)
	if err != nil {
		return err
	}
	defer clear(encoded[:])

	return c.Verify(ctx, protocol.VerifyRequest{Reference: protocol.ApplicationPIN, Data: encoded[:]})
}

// ChangePIN replaces the application PIN. Both values use the standard encoding.
func (c *Client) ChangePIN(ctx context.Context, current, replacement string) error {
	oldPIN, err := EncodePIN(current)
	if err != nil {
		return err
	}
	defer clear(oldPIN[:])

	newPIN, err := EncodePIN(replacement)
	if err != nil {
		return err
	}
	defer clear(newPIN[:])

	return c.ChangeReferenceData(ctx, protocol.ApplicationPIN, oldPIN, newPIN)
}

// UnblockPIN resets the application PIN's retry counter and replaces the PIN
// using the standard PIV encoding. PUK contains the card's eight-byte reset
// code. An incorrect PUK consumes a retry; caller-specific PUK padding is kept.
func (c *Client) UnblockPIN(ctx context.Context, puk [8]byte, replacement string) error {
	defer clear(puk[:])

	newPIN, err := EncodePIN(replacement)
	if err != nil {
		return err
	}
	defer clear(newPIN[:])

	return c.ResetRetryCounter(ctx, puk, newPIN)
}

// EncodePIN encodes a standard PIV PIN: six to eight ASCII decimal digits,
// padded on the right with FF. Use Verify for card-specific PIN encodings.
func EncodePIN(pin string) ([8]byte, error) {
	var encoded [8]byte
	if len(pin) < 6 || len(pin) > len(encoded) {
		return encoded, fmt.Errorf("piv: PIN must contain six to eight ASCII digits")
	}

	for _, digit := range []byte(pin) {
		if digit < '0' || digit > '9' {
			return encoded, fmt.Errorf("piv: PIN must contain six to eight ASCII digits")
		}
	}

	for i := range encoded {
		encoded[i] = 0xff
	}

	copy(encoded[:], pin)

	return encoded, nil
}
