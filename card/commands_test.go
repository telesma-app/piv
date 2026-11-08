package card

import (
	"bytes"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

func TestGetDataReadsEachTime(t *testing.T) {
	command := []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 7, 0}
	d, _ := newDevice(t,
		exchangeStep{command: command, response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1, 1}}},
		exchangeStep{command: command, response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1, 2}}},
	)

	for _, want := range []byte{1, 2} {
		data, err := d.GetData(t.Context(), protocol.CardCapabilityContainer)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(data, []byte{want}) {
			t.Errorf("GetData = %x, want %02x", data, want)
		}
	}
}
