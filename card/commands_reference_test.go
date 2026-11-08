package card

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestEncodedPINMaintenancePreservesCallerValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command []byte
		run     func(context.Context, *Device, [8]byte, [8]byte) error
	}{
		{
			name: "ChangeReferenceData",
			command: []byte{0, 0x24, 0, 0x81, 16,
				1, 2, 3, 4, 5, 6, 0xff, 0xff, 6, 5, 4, 3, 2, 1, 0xff, 0xff},
			run: func(ctx context.Context, d *Device, current, replacement [8]byte) error {
				return d.ChangeReferenceData(ctx, protocol.PUK, current, replacement)
			},
		},
		{
			name: "ResetRetryCounter",
			command: []byte{0, 0x2c, 0, 0x80, 16,
				6, 5, 4, 3, 2, 1, 0xff, 0xff, 1, 2, 3, 4, 5, 6, 0xff, 0xff},
			run: func(ctx context.Context, d *Device, current, replacement [8]byte) error {
				return d.ResetRetryCounter(ctx, replacement, current)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := [8]byte{1, 2, 3, 4, 5, 6, 0xff, 0xff}
			replacement := [8]byte{6, 5, 4, 3, 2, 1, 0xff, 0xff}
			d, raw := newDevice(t, exchangeStep{
				command: tc.command, response: iso7816.Response{Status: 0x9000},
			})

			if err := tc.run(t.Context(), d, current, replacement); err != nil {
				t.Fatal(err)
			}

			if current != [8]byte{1, 2, 3, 4, 5, 6, 0xff, 0xff} || replacement != [8]byte{6, 5, 4, 3, 2, 1, 0xff, 0xff} {
				t.Fatal("PIN maintenance changed caller-owned values")
			}

			if raw.calls != 1 || raw.closeCalls != 0 {
				t.Errorf("%s performed %d exchanges and %d closes, want 1 and 0", tc.name, raw.calls, raw.closeCalls)
			}
		})
	}
}

func TestVerifyInvalidationClosesOwnedSession(t *testing.T) {
	want := &transport.DeviceInvalidatedError{Err: io.ErrUnexpectedEOF}
	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0x20, 0, 0x96, 6, 1, 2, 3, 4, 5, 6}, err: want,
	})

	err := d.Verify(t.Context(), protocol.VerifyRequest{
		Reference: protocol.PrimaryFingerOCC, Data: []byte{1, 2, 3, 4, 5, 6},
	})
	if !errors.Is(err, want) || raw.closeCalls != 1 {
		t.Fatalf("Verify = %v, close count = %d; want invalidation and one close", err, raw.closeCalls)
	}

	if err := d.ChangePIN(t.Context(), "123456", "876543"); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("ChangePIN after invalidation = %v, want ErrClosedPipe", err)
	}
}
