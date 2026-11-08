package card

import (
	"context"

	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// ReferenceStatus queries a reference's security status without submitting
// authentication data or consuming a retry.
func (d *Device) ReferenceStatus(ctx context.Context, reference protocol.KeyReference) (client.ReferenceStatus, error) {
	if err := d.lock(ctx); err != nil {
		return client.ReferenceStatus{}, err
	}
	defer d.unlock()

	status, err := d.client.ReferenceStatus(ctx, reference)

	return status, d.operationError(err)
}

// ResetSecurityStatus clears a reference's security status using VERIFY P1=FF.
// It does not submit reference data.
func (d *Device) ResetSecurityStatus(ctx context.Context, reference protocol.KeyReference) error {
	return d.Verify(ctx, protocol.VerifyRequest{Reference: reference, ResetSecurityStatus: true})
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

// ChangePIN replaces the application PIN using the standard PIV encoding.
// An incorrect current PIN consumes a retry.
func (d *Device) ChangePIN(ctx context.Context, current, replacement string) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.ChangePIN(ctx, current, replacement))
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
