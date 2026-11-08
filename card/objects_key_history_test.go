package card

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestGetKeyHistoryDistinguishesAbsenceAndCounts(t *testing.T) {
	url := "http://certs.example/" + strings.Repeat("a", 64)
	populated := []byte{0xc1, 1, 2, 0xc2, 1, 1}
	populated = append(populated, readTLV(0xf3, []byte(url))...)

	populated = append(populated, 0xfe, 0)
	for _, tc := range []struct {
		name     string
		response iso7816.Response
		want     protocol.KeyHistory
		status   iso7816.StatusWord
		parseErr bool
	}{
		{name: "absent", response: iso7816.Response{Status: 0x6a82}, status: 0x6a82},
		{name: "present zero", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 8, 0xc1, 1, 0, 0xc2, 1, 0, 0xfe, 0}}},
		{
			name: "on-card and off-card", response: iso7816.Response{Status: 0x9000, Data: readTLV(0x53, populated)},
			want: protocol.KeyHistory{KeysWithOnCardCerts: 2, KeysWithOffCardCerts: 1, OffCardCertURL: url},
		},
		{name: "malformed", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 3, 0xc1, 1, 0}}, parseErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, _ := newDevice(t, exchangeStep{
				command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0c, 0}, response: tc.response,
			})

			history, err := d.GetKeyHistory(t.Context())
			if tc.status != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.status {
					t.Fatalf("GetKeyHistory = %v, want APDU %s", err, tc.status)
				}
			} else if tc.parseErr {
				if !errors.Is(err, protocol.ErrInvalidResponse) {
					t.Fatalf("GetKeyHistory = %v, want ErrInvalidResponse", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}

			if history != tc.want {
				t.Errorf("history = %+v, want %+v", history, tc.want)
			}
		})
	}
}

func TestGetKeyHistoryInvalidationClosesSession(t *testing.T) {
	cause := errors.New("card removed")
	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0c, 0},
		err:     &transport.DeviceInvalidatedError{Err: cause},
	})

	_, err := d.GetKeyHistory(t.Context())

	var invalidated *transport.DeviceInvalidatedError
	if !errors.As(err, &invalidated) || !errors.Is(err, cause) || raw.closeCalls != 1 {
		t.Fatalf("GetKeyHistory = %v, close count %d; want invalidation with cause", err, raw.closeCalls)
	}

	if _, err := d.GetKeyHistory(t.Context()); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("GetKeyHistory after invalidation = %v, want ErrClosedPipe", err)
	}
}
