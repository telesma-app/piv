package card

import (
	"context"

	"github.com/telesma-app/piv/protocol"
)

// GetCHUID reads the Card Holder Unique Identifier without verifying its issuer
// signature or evaluating expiration. The result is not cached.
func (d *Device) GetCHUID(ctx context.Context) (protocol.CHUID, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.CHUID{}, err
	}
	defer d.unlock()

	chuid, err := d.client.GetCHUID(ctx)

	return chuid, d.operationError(err)
}

// GetCCC reads the Card Capability Container without authenticating its contents.
// It describes GSC-IS compatibility, not supported cryptographic algorithms.
// The result is not cached.
func (d *Device) GetCCC(ctx context.Context) (protocol.CCC, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.CCC{}, err
	}
	defer d.unlock()

	ccc, err := d.client.GetCCC(ctx)

	return ccc, d.operationError(err)
}

// GetPrintedInformation reads the optional Printed Information object without
// authenticating its contents. The result is not cached; absence is an APDU error.
func (d *Device) GetPrintedInformation(ctx context.Context) (protocol.PrintedInfo, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.PrintedInfo{}, err
	}
	defer d.unlock()

	info, err := d.client.GetPrintedInformation(ctx)

	return info, d.operationError(err)
}
