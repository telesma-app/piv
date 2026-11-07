package client

import (
	"context"
	"errors"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/internal/bertlv"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

type objectReadCase struct {
	name     string
	selector byte
	contents func(byte) []byte
	read     func(context.Context, *Client) (byte, error)
}

func objectReadCases() []objectReadCase {
	return []objectReadCase{
		{
			name: "CHUID", selector: 0x02,
			contents: func(marker byte) []byte {
				data := append([]byte{0x30, 25}, make([]byte, 25)...)
				data = append(data, 0x34, 16, marker)
				data = append(data, make([]byte, 15)...)

				return append(data, []byte("\x35\x0820301231\xfe\x00")...)
			},
			read: func(ctx context.Context, c *Client) (byte, error) {
				chuid, err := c.GetCHUID(ctx)
				return chuid.GUID[0], err
			},
		},
		{
			name: "CCC", selector: 0x07,
			contents: func(marker byte) []byte { return []byte{0xf5, 1, marker, 0xfe, 0} },
			read: func(ctx context.Context, c *Client) (byte, error) {
				ccc, err := c.GetCCC(ctx)
				return ccc.DataModel, err
			},
		},
		{
			name: "printed information", selector: 0x09,
			contents: func(marker byte) []byte {
				return append([]byte{1, 1, marker}, []byte("\x02\x00\x04\x092030DEC31\x05\x00\x06\x0f123456789012345\xfe\x00")...)
			},
			read: func(ctx context.Context, c *Client) (byte, error) {
				info, err := c.GetPrintedInformation(ctx)
				if err != nil {
					return 0, err
				}

				return info.Name[0], nil
			},
		},
	}
}

func TestTypedObjectReads(t *testing.T) {
	for _, test := range objectReadCases() {
		t.Run(test.name, func(t *testing.T) {
			command := []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, test.selector, 0}
			c := NewClient(newScript(t,
				exchangeStep{command: command, response: iso7816.Response{
					Status: 0x9000, Data: bertlv.Append(nil, 0x53, test.contents('A')),
				}},
				exchangeStep{command: command, response: iso7816.Response{
					Status: 0x9000, Data: bertlv.Append(nil, 0x53, test.contents('B')),
				}},
			))

			for _, want := range []byte{'A', 'B'} {
				if got, err := test.read(t.Context(), c); err != nil || got != want {
					t.Fatalf("read = %02x, %v, want %02x", got, err, want)
				}
			}
		})
	}
}

func TestTypedObjectReadsPreserveErrors(t *testing.T) {
	cause := errors.New("card disconnected")

	for _, object := range objectReadCases() {
		t.Run(object.name, func(t *testing.T) {
			for _, test := range []struct {
				name     string
				response iso7816.Response
				err      error
				want     error
				status   iso7816.StatusWord
			}{
				{name: "absent", response: iso7816.Response{Status: 0x6a82}, status: 0x6a82},
				{name: "access denied", response: iso7816.Response{Status: 0x6982}, status: 0x6982},
				{name: "malformed object", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1}}, want: protocol.ErrInvalidResponse},
				{name: "malformed contents", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 2, 0xfe, 0}}, want: protocol.ErrInvalidResponse},
				{name: "transport", err: cause, want: cause},
				{name: "canceled", err: context.Canceled, want: context.Canceled},
				{name: "invalidated", err: &transport.DeviceInvalidatedError{Err: cause}, want: cause},
			} {
				t.Run(test.name, func(t *testing.T) {
					c := NewClient(newScript(t, exchangeStep{
						command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, object.selector, 0},
						response: test.response, err: test.err,
					}))
					_, err := object.read(t.Context(), c)

					if test.status != 0 {
						var apdu *iso7816.APDUError
						if !errors.As(err, &apdu) || apdu.StatusWord() != test.status {
							t.Fatalf("read error = %v, want APDU %04x", err, uint16(test.status))
						}
					} else if !errors.Is(err, test.want) {
						t.Fatalf("read error = %v, want %v", err, test.want)
					}

					if test.name == "invalidated" {
						var invalidated *transport.DeviceInvalidatedError
						if !errors.As(err, &invalidated) {
							t.Errorf("lost invalidation type: %v", err)
						}
					}
				})
			}
		})
	}
}
