package iso7816

import (
	"bytes"
	"reflect"
	"testing"

	baseiso7816 "github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

func TestApplicationPropertiesRetainInitialSelect(t *testing.T) {
	body := []byte{
		0x4f, 3, 1, 2, 3,
		0x79, 4, 0x4f, 2, 0xa0, 1,
		0x50, 3, 'P', 'I', 'V',
		0x5f, 0x50, 3, 'u', 'r', 'l',
		0xac, 9, 0x80, 1, 0xee, 0x80, 1, 0x11, 6, 1, 0,
	}
	response := append([]byte{0x61, byte(len(body))}, body...)
	response = append(response, 0x90, 0)
	raw := &fakeCard{t: t, exchanges: []exchange{
		{request: selectAPDU, response: response},
		{request: []byte{0, 0x20, 0, 0x80}, response: []byte{0x63, 0xc3}, after: func() { clear(response) }},
	}}

	connection, err := Open(t.Context(), raw)
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(connection)

	t.Cleanup(func() { _ = device.Close() })

	want := protocol.ApplicationPropertyTemplate{
		AID: []byte{1, 2, 3}, TagAllocationAuthorityAID: []byte{0xa0, 1},
		ApplicationLabel: "PIV", ApplicationURL: "url", Algorithms: []protocol.Algorithm{0xee, protocol.ECCP256},
	}

	for range 2 {
		if got := connection.ApplicationProperties(); !reflect.DeepEqual(got, want) {
			t.Fatalf("transport properties = %+v, want %+v", got, want)
		}

		got, ok := device.ApplicationProperties()
		if !ok || !reflect.DeepEqual(got, want) || len(raw.exchanges) != 1 {
			t.Fatalf("card properties = %+v, %v; remaining APDUs=%d", got, ok, len(raw.exchanges))
		}
	}

	if _, err := device.Exchange(t.Context(), baseiso7816.Command{INS: 0x20, P2: 0x80}); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(response, make([]byte, len(response))) {
		t.Fatal("response reuse was not exercised")
	}

	if err := device.Close(); err != nil {
		t.Fatal(err)
	}

	got, ok := device.ApplicationProperties()
	if !ok || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(connection.ApplicationProperties(), want) {
		t.Fatalf("properties after reuse and close = %+v, %v; want %+v", got, ok, want)
	}

	if len(raw.exchanges) != 0 || raw.closeCalls != 1 {
		t.Errorf("remaining APDUs=%d closes=%d", len(raw.exchanges), raw.closeCalls)
	}
}
