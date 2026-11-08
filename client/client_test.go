package client

import (
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestTransportErrorPreserved(t *testing.T) {
	want := errors.New("disconnected")
	c := NewClient(newScript(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0}, err: want,
	}))

	_, err := c.GetData(t.Context(), protocol.CardCapabilityContainer)
	if !errors.Is(err, want) {
		t.Errorf("error = %v, want underlying cause", err)
	}
}
