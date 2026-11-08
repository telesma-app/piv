package card

import (
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/iso7816/scp11"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

var _ transport.Device = (*scp11.Transport)(nil)

func TestISO7816InvalidationClosesCardSession(t *testing.T) {
	cause := errors.New("secure channel authentication failed")
	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0},
		err:     &iso7816.DeviceInvalidatedError{Err: cause},
	})

	_, err := d.GetData(t.Context(), protocol.CardCapabilityContainer)

	var invalidated *transport.DeviceInvalidatedError
	if !errors.As(err, &invalidated) || !errors.Is(err, cause) {
		t.Fatalf("GetData = %v, want invalidated secure channel", err)
	}

	if raw.closeCalls != 1 {
		t.Fatalf("Close calls = %d, want 1", raw.closeCalls)
	}

	if _, err := d.GetData(t.Context(), protocol.CardCapabilityContainer); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("GetData after invalidation = %v, want closed pipe", err)
	}

	if raw.calls != 1 || raw.closeCalls != 1 {
		t.Errorf("invalidated session performed I/O: exchanges=%d closes=%d", raw.calls, raw.closeCalls)
	}
}
