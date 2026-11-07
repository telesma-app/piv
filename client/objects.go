package client

import (
	"context"

	"github.com/telesma-app/piv/protocol"
)

// GetCHUID reads the Card Holder Unique Identifier without verifying its issuer
// signature or evaluating expiration. An absent object remains an APDU error.
func (c *Client) GetCHUID(ctx context.Context) (protocol.CHUID, error) {
	data, err := c.GetData(ctx, protocol.CardholderUniqueIdentifier)
	if err != nil {
		return protocol.CHUID{}, err
	}

	return protocol.ParseCHUID(data)
}

// GetCCC reads the Card Capability Container without authenticating its contents.
// It describes GSC-IS compatibility, not supported cryptographic algorithms.
func (c *Client) GetCCC(ctx context.Context) (protocol.CCC, error) {
	data, err := c.GetData(ctx, protocol.CardCapabilityContainer)
	if err != nil {
		return protocol.CCC{}, err
	}

	return protocol.ParseCCC(data)
}

// GetPrintedInformation reads the optional Printed Information object without
// authenticating its contents. An absent object remains an APDU error.
func (c *Client) GetPrintedInformation(ctx context.Context) (protocol.PrintedInfo, error) {
	data, err := c.GetData(ctx, protocol.PrintedInformation)
	if err != nil {
		return protocol.PrintedInfo{}, err
	}

	return protocol.ParsePrintedInformation(data)
}
