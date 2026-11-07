package client

import (
	"context"
	"fmt"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

// ReferenceStatus reports the result of an empty VERIFY. Retries is meaningful
// when Verified is false and is taken from an explicit 63Cx response. A zero
// retry count means the reference is blocked.
type ReferenceStatus struct {
	Verified bool
	Retries  int
}

// ReferenceDataError reports a reference-data check returning an explicit 63Cx
// retry count. It preserves the APDU status for errors.As and never includes secrets.
type ReferenceDataError struct {
	Reference protocol.KeyReference
	Retries   int
	Status    iso7816.StatusWord
}

func (e *ReferenceDataError) Error() string {
	return fmt.Sprintf("piv: reference %02x verification failed (%d retries, SW=%s)", byte(e.Reference), e.Retries, e.Status)
}

func (e *ReferenceDataError) Unwrap() error {
	return &iso7816.APDUError{SW1: e.Status.SW1(), SW2: e.Status.SW2()}
}

func retryStatus(status iso7816.StatusWord) (int, bool) {
	if status&0xfff0 == 0x63c0 {
		return int(status & 0x0f), true
	}

	return 0, false
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

// Verify sends the supplied VERIFY operation, including empty status queries,
// security-status resets, and encoded PIN, pairing-code, or OCC data. Data is
// borrowed unchanged; its encoding belongs to the caller. An incorrect value
// can consume a retry.
func (c *Client) Verify(ctx context.Context, request protocol.VerifyRequest) error {
	var p1 byte
	if request.ResetSecurityStatus {
		p1 = 0xff
	}

	return c.referenceCommand(ctx, protocol.Verify, p1, request.Reference, request.Data)
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

// ChangeReferenceData replaces a PIN or PUK using eight-byte encoded values.
// Reference is ApplicationPIN, GlobalPIN, or PUK (SP 800-73-5 Part 2,
// Sec. 3.2.2). An incorrect current value consumes a retry.
func (c *Client) ChangeReferenceData(ctx context.Context, reference protocol.KeyReference, current, replacement [8]byte) error {
	defer clear(current[:])
	defer clear(replacement[:])

	var data [16]byte
	copy(data[:8], current[:])

	copy(data[8:], replacement[:])
	defer clear(data[:])

	return c.referenceCommand(ctx, protocol.ChangeReferenceData, 0, reference, data[:])
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

// ResetRetryCounter resets the application PIN's retry counter and replaces
// its encoded value. PUK and replacement contain exactly eight encoded bytes;
// card-specific padding belongs to the caller. An incorrect PUK consumes a PUK
// retry.
func (c *Client) ResetRetryCounter(ctx context.Context, puk, replacement [8]byte) error {
	defer clear(puk[:])
	defer clear(replacement[:])

	var data [16]byte
	copy(data[:8], puk[:])

	copy(data[8:], replacement[:])
	defer clear(data[:])

	return c.referenceCommand(ctx, protocol.ResetRetryCounter, 0, protocol.ApplicationPIN, data[:])
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

func (c *Client) referenceCommand(ctx context.Context, instruction protocol.Instruction, p1 byte, reference protocol.KeyReference, data []byte) error {
	response, err := c.transport.Exchange(ctx, iso7816.Command{
		INS: byte(instruction), P1: p1, P2: byte(reference), Data: data, Encoding: iso7816.EncodingShort,
	})
	if err != nil {
		return err
	}

	if retries, ok := retryStatus(response.Status); ok {
		if len(response.Data) != 0 {
			return protocol.ErrInvalidResponse
		}

		if instruction == protocol.ResetRetryCounter {
			reference = protocol.PUK
		}

		return &ReferenceDataError{Reference: reference, Retries: retries, Status: response.Status}
	}

	if err := response.APDUError(); err != nil {
		return err
	}

	if len(response.Data) != 0 {
		return protocol.ErrInvalidResponse
	}

	return nil
}
