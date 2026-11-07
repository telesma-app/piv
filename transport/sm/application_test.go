package sm

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

func TestApplicationPropertiesRetainHandshakeSelection(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		peer := newHandshakePeer(t, suite)
		peer.handshake = func(response iso7816.Response) iso7816.Response {
			clear(peer.application)
			return response
		}

		channel, err := Open(t.Context(), peer, peer.parameters())
		if err != nil {
			t.Fatal(err)
		}

		device := card.New(channel)

		t.Cleanup(func() { _ = device.Close() })

		want := protocol.ApplicationPropertyTemplate{
			AID: []byte{1}, TagAllocationAuthorityAID: []byte{2}, Algorithms: []protocol.Algorithm{suite.algorithm},
		}

		if !bytes.Equal(peer.application, make([]byte, len(peer.application))) {
			t.Fatal("response reuse during handshake was not exercised")
		}

		for range 2 {
			if got := channel.ApplicationProperties(); !reflect.DeepEqual(got, want) {
				t.Fatalf("channel properties = %+v, want %+v", got, want)
			}

			got, ok := device.ApplicationProperties()
			if !ok || !reflect.DeepEqual(got, want) || len(peer.requests) != 2 {
				t.Fatalf("card properties = %+v, %v; exchanges=%d", got, ok, len(peer.requests))
			}
		}

		if err := device.Close(); err != nil {
			t.Fatal(err)
		}

		got, ok := device.ApplicationProperties()
		if !ok || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(channel.ApplicationProperties(), want) {
			t.Fatalf("properties after Close = %+v, %v", got, ok)
		}
	})
}
