package iso7816

import (
	"bytes"
	"context"
	"testing"
)

var (
	selectAPDU     = []byte{0x00, 0xa4, 0x04, 0x00, 0x09, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00}
	selectResponse = []byte{
		0x61, 0x11,
		0x4f, 0x06, 0, 0, 0x10, 0, 1, 0,
		0x79, 0x07, 0x4f, 0x05, 0xa0, 0, 0, 3, 8,
		0x90, 0,
	}
)

type exchange struct {
	request  []byte
	response []byte
	err      error
	after    func()
}

type fakeCard struct {
	t          testing.TB
	exchanges  []exchange
	closeCalls int
	closeErr   error
}

func (c *fakeCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	c.t.Helper()

	if len(c.exchanges) == 0 {
		c.t.Fatalf("unexpected APDU: %x", apdu)
	}

	next := c.exchanges[0]

	c.exchanges = c.exchanges[1:]
	if !bytes.Equal(apdu, next.request) {
		c.t.Fatalf("APDU = %x, want %x", apdu, next.request)
	}

	if next.after != nil {
		next.after()
	}

	return next.response, next.err
}

func (c *fakeCard) Close() error {
	c.closeCalls++
	return c.closeErr
}
