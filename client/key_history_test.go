package client

import (
	"errors"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

func TestGetKeyHistory(t *testing.T) {
	url := "http://example.test/0123456789abcdef"
	inner := []byte{0xc1, 1, 2, 0xc2, 1, 1, 0xf3, byte(len(url))}
	inner = append(inner, url...)
	inner = append(inner, 0xfe, 0)
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0c, 0},
		response: iso7816.Response{Status: 0x9000, Data: bertlv.Append(nil, 0x53, inner)},
	}))

	history, err := c.GetKeyHistory(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	want := protocol.KeyHistory{KeysWithOnCardCerts: 2, KeysWithOffCardCerts: 1, OffCardCertURL: url}
	if history != want {
		t.Errorf("history = %+v, want %+v", history, want)
	}
}

func TestGetKeyHistoryPreservesErrors(t *testing.T) {
	cause := errors.New("connection lost")
	for _, tc := range []struct {
		name     string
		response iso7816.Response
		err      error
		want     error
		status   iso7816.StatusWord
	}{
		{name: "transport", err: cause, want: cause},
		{name: "absent", response: iso7816.Response{Status: 0x6a82}, status: 0x6a82},
		{name: "denied", response: iso7816.Response{Status: 0x6982}, status: 0x6982},
		{name: "outer template", response: iso7816.Response{Status: 0x9000, Data: []byte{0x7e, 0}}, want: protocol.ErrInvalidResponse},
		{name: "missing count", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 3, 0xc1, 1, 0}}, want: protocol.ErrInvalidResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0c, 0}, response: tc.response, err: tc.err,
			}))

			_, err := c.GetKeyHistory(t.Context())
			if tc.status != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.status {
					t.Fatalf("error = %v, want APDU %s", err, tc.status)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}
