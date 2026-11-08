package card

import (
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

func TestReferenceStatusReadsCardState(t *testing.T) {
	command := []byte{0, 0x20, 0, 0x80}
	d, _ := newDevice(t,
		exchangeStep{command: command, response: iso7816.Response{Status: 0x63c3}},
		exchangeStep{command: command, response: iso7816.Response{Status: 0x9000}},
	)

	status, err := d.ReferenceStatus(t.Context(), protocol.ApplicationPIN)
	if err != nil {
		t.Fatal(err)
	}

	if status.Verified || status.Retries != 3 {
		t.Errorf("ReferenceStatus = %+v, want unverified with three retries", status)
	}

	status, err = d.ReferenceStatus(t.Context(), protocol.ApplicationPIN)
	if err != nil {
		t.Fatal(err)
	}

	if !status.Verified {
		t.Errorf("ReferenceStatus = %+v, want verified", status)
	}
}

func TestPINMaintenanceUsesOwnedSession(t *testing.T) {
	for _, tc := range []struct {
		name    string
		step    exchangeStep
		run     func(context.Context, *Device) error
		retries *client.ReferenceDataError
	}{
		{
			name: "VerifyPIN",
			step: exchangeStep{
				command:  []byte{0, 0x20, 0, 0x80, 8, '1', '2', '3', '4', '5', '6', 0xff, 0xff},
				response: iso7816.Response{Status: 0x63c2},
			},
			run: func(ctx context.Context, d *Device) error {
				return d.VerifyPIN(ctx, "123456")
			},
			retries: &client.ReferenceDataError{Retries: 2},
		},
		{
			name: "ChangePIN",
			step: exchangeStep{
				command: []byte{0, 0x24, 0, 0x80, 16,
					'1', '2', '3', '4', '5', '6', 0xff, 0xff, '8', '7', '6', '5', '4', '3', 0xff, 0xff},
				response: iso7816.Response{Status: 0x9000},
			},
			run: func(ctx context.Context, d *Device) error {
				return d.ChangePIN(ctx, "123456", "876543")
			},
		},
		{
			name: "ResetSecurityStatus",
			step: exchangeStep{
				command: []byte{0, 0x20, 0xff, 0x80}, response: iso7816.Response{Status: 0x9000},
			},
			run: func(ctx context.Context, d *Device) error {
				return d.ResetSecurityStatus(ctx, protocol.ApplicationPIN)
			},
		},
		{
			name: "UnblockPIN",
			step: exchangeStep{
				command: []byte{0, 0x2c, 0, 0x80, 16,
					1, 2, 3, 4, 5, 6, 7, 8, '1', '2', '3', '4', '5', '6', '7', '8'},
				response: iso7816.Response{Status: 0x9000},
			},
			run: func(ctx context.Context, d *Device) error {
				return d.UnblockPIN(ctx, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, "12345678")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, raw := newDevice(t, tc.step)

			err := tc.run(t.Context(), d)
			if tc.retries != nil {
				var referenceError *client.ReferenceDataError
				if !errors.As(err, &referenceError) || referenceError.Retries != tc.retries.Retries {
					t.Fatalf("%s = %v, want %d retries", tc.name, err, tc.retries.Retries)
				}
			} else if err != nil {
				t.Fatal(err)
			}

			if raw.calls != 1 || raw.closeCalls != 0 {
				t.Errorf("%s performed %d exchanges and %d closes, want 1 and 0", tc.name, raw.calls, raw.closeCalls)
			}
		})
	}
}
