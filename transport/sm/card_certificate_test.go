package sm

import (
	"bytes"
	"context"
	"testing"

	"github.com/telesma-app/iso7816"
)

func TestCardCertificateRetainsAuthenticatedIdentity(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		peer := newHandshakePeer(t, suite)
		guid := [16]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0x4d, 0xef, 0x80, 1, 2, 3, 4, 5, 6, 7}
		body := certificateBody(peer.issuer, guid[:], peer.static.PublicKey().Bytes(), 0)
		// Retain a valid noncanonical BER length rather than re-encoding the CVC.
		body = append([]byte{0x5f, 0x29, 0x81, 1}, body[3:]...)
		peer.certificate = signCertificate(t, body, peer.signer, false)
		wantRaw := bytes.Clone(peer.certificate)

		var handshakeBuffer []byte

		peer.handshake = func(response iso7816.Response) iso7816.Response {
			handshakeBuffer = response.Data
			return response
		}

		channel := openHandshakePeer(t, peer)
		assertCertificate := func() {
			t.Helper()

			got := channel.CardCertificate()
			if got.GUID != guid || !got.PublicKey.Equal(peer.static.PublicKey()) || !bytes.Equal(got.Raw, wantRaw) {
				t.Fatalf("CardCertificate = %+v, want GUID %x, public key %x, CVC %x", got, guid, peer.static.PublicKey().Bytes(), wantRaw)
			}
		}
		assertCertificate()

		if len(peer.requests) != 2 {
			t.Fatalf("CardCertificate sent commands: %d", len(peer.requests))
		}

		peer.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
			clear(handshakeBuffer)
			return peer.protectedResponse([]byte("public object"), 0x9000), nil
		}

		if _, err := channel.Exchange(t.Context(), readCommand()); err != nil {
			t.Fatal(err)
		}

		assertCertificate()

		if err := channel.Close(); err != nil {
			t.Fatal(err)
		}

		assertCertificate()
	})
}
