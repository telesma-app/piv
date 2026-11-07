package card

import (
	"context"
	"errors"

	"github.com/telesma-app/piv/protocol"
)

var (
	ErrSecureMessagingRequired = errors.New("piv: NIST PIV secure messaging required")
	ErrVCINotSupported         = errors.New("piv: virtual contact interface is not supported")
)

// pivSecureMessaging identifies the active NIST PIV secure messaging transport.
// Other secure-channel protocols do not establish the PIV VCI conditions.
type pivSecureMessaging interface {
	PIVSecureMessaging() bool
}

// VerifyPairingCode submits an eight-digit pairing code under the operation
// gate. A failed check clears the card's pairing security status; pairing has
// no retry counter. Over contactless, use a NIST PIV secure messaging transport.
// This call does not check VCI policy; CheckVCI performs that workflow.
func (d *Device) VerifyPairingCode(ctx context.Context, code string) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	return d.operationError(d.client.VerifyPairingCode(ctx, code))
}

// CheckVCI checks the current virtual contact interface conditions under
// the operation gate (SP 800-73-5 Part 2, Table 2, Note 2). It requires active
// NIST PIV secure messaging and reads the Discovery Object over that channel.
// If the policy requires pairing, an empty VERIFY checks that pairing was
// already authenticated; use VerifyPairingCode to submit the code explicitly.
//
// The card establishes VCI from these conditions, without a separate activation
// command. No VCI status is cached: resetting pairing security status or ending
// secure messaging changes the conditions for subsequent commands. A missing
// Discovery Object and a failed pairing-status check retain their APDU errors.
func (d *Device) CheckVCI(ctx context.Context) error {
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()

	sm, ok := d.transport.(pivSecureMessaging)
	if !ok || !sm.PIVSecureMessaging() {
		return ErrSecureMessagingRequired
	}

	discovery, err := d.client.GetDiscovery(ctx)
	if err != nil {
		return d.operationError(err)
	}

	policy := discovery.PINUsagePolicy.Flags
	if policy&protocol.PINUsageVCI == 0 {
		return ErrVCINotSupported
	}

	if policy&protocol.PINUsageVCIWithoutPairingCode != 0 {
		return nil
	}

	return d.operationError(d.client.Verify(ctx, protocol.VerifyRequest{Reference: protocol.PairingCode}))
}
