package client

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

func TestGetDiscovery(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0},
		response: iso7816.Response{Status: 0x9000, Data: []byte{
			0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
			0x5f, 0x2f, 2, 0x60, 0x20,
		}},
	}))

	got, err := c.GetDiscovery(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.AID, []byte{0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0}) ||
		got.PINUsagePolicy.Flags != protocol.PINUsageApplicationPIN|protocol.PINUsageGlobalPIN ||
		got.PINUsagePolicy.PrimaryPIN != protocol.PINPreferenceGlobalPIN {
		t.Errorf("discovery = %+v, want PIV AID and Global PIN preference", got)
	}
}

func TestGetDiscoveryPreservesAbsentObject(t *testing.T) {
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0},
		response: iso7816.Response{Status: 0x6a82},
	}))

	_, err := c.GetDiscovery(t.Context())

	var apdu *iso7816.APDUError
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6a82 {
		t.Fatalf("GetDiscovery error = %v, want APDU 6A82", err)
	}
}
