package card

import (
	"context"

	"github.com/telesma-app/piv/protocol"
)

// Verify sends an encoded VERIFY operation under the card's operation gate.
// This includes empty status queries, security-status resets, and PIN,
// pairing-code, or OCC authentication data. Request data is borrowed unchanged.
// An incorrect value can consume a retry.
// Separate calls do not form an atomic authentication workflow.
func (d *Device) Verify(ctx context.Context, request protocol.VerifyRequest) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.Verify(ctx, request))
}

// VerifyPIN verifies the standard six-to-eight digit application PIN.
// An incorrect PIN consumes a retry. Verification and a subsequent operation
// are separate calls; PrivateKey.Sign keeps VERIFY and signing together.
func (d *Device) VerifyPIN(ctx context.Context, pin string) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.VerifyPIN(ctx, pin))
}

// ResetSecurityStatus clears a reference's security status using VERIFY P1=FF.
// It does not submit reference data.
func (d *Device) ResetSecurityStatus(ctx context.Context, reference protocol.KeyReference) error {
	return d.Verify(ctx, protocol.VerifyRequest{Reference: reference, ResetSecurityStatus: true})
}

// ChangeReferenceData replaces a PIN or PUK using eight-byte encoded values.
// Reference is ApplicationPIN, GlobalPIN, or PUK (SP 800-73-5 Part 2,
// Sec. 3.2.2). An incorrect current value consumes a retry. Card-specific
// padding belongs to the caller.
func (d *Device) ChangeReferenceData(ctx context.Context, reference protocol.KeyReference, current, replacement [8]byte) error {
	defer clear(current[:])
	defer clear(replacement[:])

	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ChangeReferenceData(ctx, reference, current, replacement))
}

// ChangePIN replaces the application PIN using the standard PIV encoding.
// An incorrect current PIN consumes a retry.
func (d *Device) ChangePIN(ctx context.Context, current, replacement string) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ChangePIN(ctx, current, replacement))
}

// ResetRetryCounter resets the application PIN's retry counter and replaces
// its value using an eight-byte PUK and eight-byte encoded replacement. Padding
// belongs to the caller. An incorrect PUK consumes a retry.
func (d *Device) ResetRetryCounter(ctx context.Context, puk, replacement [8]byte) error {
	defer clear(puk[:])
	defer clear(replacement[:])

	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ResetRetryCounter(ctx, puk, replacement))
}

// UnblockPIN resets the application PIN's retry counter and replaces the PIN
// using the standard PIV encoding. The eight-byte PUK keeps caller-supplied
// padding. An incorrect PUK consumes a retry.
func (d *Device) UnblockPIN(ctx context.Context, puk [8]byte, replacement string) error {
	defer clear(puk[:])

	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.UnblockPIN(ctx, puk, replacement))
}
