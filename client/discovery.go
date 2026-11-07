package client

import (
	"context"

	"github.com/telesma-app/piv/protocol"
)

// GetDiscovery reads the optional Discovery Object, including its PIN Usage
// Policy. An absent object remains an iso7816.APDUError (6A82). The policy is
// returned as metadata; it does not select a PIN or establish a VCI.
func (c *Client) GetDiscovery(ctx context.Context) (protocol.Discovery, error) {
	data, err := c.GetData(ctx, protocol.DiscoveryObject)
	if err != nil {
		return protocol.Discovery{}, err
	}

	return protocol.ParseDiscovery(data)
}
