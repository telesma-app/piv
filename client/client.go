package client

import (
	"context"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/transport"
)

// Client sends PIV commands through a borrowed transport.
type Client struct {
	transport transport.APDU
}

// NewClient borrows a transport without performing I/O. Select PIV before
// sending commands; backend/pcsc.Open and transport/iso7816.Open do this already.
func NewClient(transport transport.APDU) *Client {
	return &Client{transport: transport}
}

func (c *Client) exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	response, err := c.transport.Exchange(ctx, command)
	if err != nil {
		return iso7816.Response{}, err
	}

	if err := response.APDUError(); err != nil {
		return iso7816.Response{}, err
	}

	return response, nil
}
