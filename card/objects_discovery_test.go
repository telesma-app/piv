package card

import (
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestGetDiscoveryReadsFreshPolicy(t *testing.T) {
	d, _ := newDevice(t,
		exchangeStep{
			command: []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0},
			response: iso7816.Response{Status: 0x9000, Data: []byte{
				0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
				0x5f, 0x2f, 2, 0x40, 0,
			}},
		},
		exchangeStep{
			command: []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0},
			response: iso7816.Response{Status: 0x9000, Data: []byte{
				0x7e, 0x12, 0x4f, 0x0b, 0xa0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0,
				0x5f, 0x2f, 2, 0x60, 0x20,
			}},
		},
	)

	first, err := d.GetDiscovery(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	second, err := d.GetDiscovery(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	if first.PINUsagePolicy.PrimaryPIN != protocol.PINPreferenceNone ||
		second.PINUsagePolicy.PrimaryPIN != protocol.PINPreferenceGlobalPIN {
		t.Errorf("PIN preferences = %x, %x; want 00, 20", first.PINUsagePolicy.PrimaryPIN, second.PINUsagePolicy.PrimaryPIN)
	}
}

func TestGetDiscoveryInvalidationClosesSession(t *testing.T) {
	cause := errors.New("connection lost")
	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 3, 0x5c, 1, 0x7e, 0},
		err:     &transport.DeviceInvalidatedError{Err: cause},
	})

	if _, err := d.GetDiscovery(t.Context()); !errors.Is(err, cause) {
		t.Fatalf("GetDiscovery error = %v, want connection loss", err)
	}

	if _, err := d.GetDiscovery(t.Context()); !errors.Is(err, io.ErrClosedPipe) || raw.closeCalls != 1 {
		t.Errorf("after invalidation: error = %v, close calls = %d", err, raw.closeCalls)
	}
}
