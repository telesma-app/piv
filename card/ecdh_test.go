package card

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func ecdhScalar(t testing.TB, curve ecdh.Curve, scalar byte) *ecdh.PrivateKey {
	t.Helper()

	width := 32
	if curve == ecdh.P384() {
		width = 48
	}

	encoded := make([]byte, width)
	encoded[width-1] = scalar

	private, err := curve.NewPrivateKey(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return private
}

func ecdhMaterial(t testing.TB, curve ecdh.Curve) (*ecdsa.PublicKey, *ecdh.PublicKey, []byte) {
	t.Helper()
	card := ecdhScalar(t, curve, 7)
	peer := ecdhScalar(t, curve, 11)

	legacyCurve := elliptic.P256()
	if curve == ecdh.P384() {
		legacyCurve = elliptic.P384()
	}

	public, err := ecdsa.ParseUncompressedPublicKey(legacyCurve, card.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}

	want, err := peer.ECDH(card.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	return public, peer.PublicKey(), want
}

func bindECDH(t testing.TB, device *Device, reference protocol.KeyReference, public *ecdsa.PublicKey) *PrivateKey {
	t.Helper()

	key, err := device.PrivateKey(reference, public)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

// Both supported curves fit one-byte TLV lengths and one short command APDU.
// Keep the wire oracle independent of the production authentication encoder.
func ecdhCommand(algorithm protocol.Algorithm, reference protocol.KeyReference, peer *ecdh.PublicKey) []byte {
	point := peer.Bytes()
	command := []byte{0, 0x87, byte(algorithm), byte(reference), byte(len(point) + 6), 0x7c, byte(len(point) + 4), 0x82, 0, 0x85, byte(len(point))}
	command = append(command, point...)

	return append(command, 0)
}

func ecdhResponse(secret []byte) iso7816.Response {
	data := []byte{0x7c, byte(len(secret) + 2), 0x82, byte(len(secret))}
	return iso7816.Response{Status: 0x9000, Data: append(data, secret...)}
}

func TestECDHMatchesStandardPrimitive(t *testing.T) {
	for _, tc := range []struct {
		name      string
		curve     ecdh.Curve
		algorithm protocol.Algorithm
	}{
		{name: "P-256", curve: ecdh.P256(), algorithm: protocol.ECCP256},
		{name: "P-384", curve: ecdh.P384(), algorithm: protocol.ECCP384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reference := range []protocol.KeyReference{protocol.KeyManagement, protocol.RetiredKey1, protocol.RetiredKey20} {
				public, peer, want := ecdhMaterial(t, tc.curve)
				device, _ := newDevice(t, exchangeStep{
					command: ecdhCommand(tc.algorithm, reference, peer), response: ecdhResponse(want),
				})
				key := bindECDH(t, device, reference, public)

				got, err := key.ECDH(t.Context(), peer, nil)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(got, want) {
					t.Errorf("slot %02x ECDH = %x, want %x", byte(reference), got, want)
				}
			}
		})
	}
}

func TestECDHPreservesLeadingZeroBytes(t *testing.T) {
	// Fixed multiples 379*G (P-256) and 197*G (P-384) have an x coordinate
	// beginning with zero. With the card scalar 1, that coordinate is the secret.
	for _, tc := range []struct {
		name      string
		curve     ecdh.Curve
		legacy    elliptic.Curve
		algorithm protocol.Algorithm
		point     string
		secret    string
	}{
		{
			name: "P-256", curve: ecdh.P256(), legacy: elliptic.P256(), algorithm: protocol.ECCP256,
			point:  "04005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00abb4c85a3d8ea29efaafa24406912dd84d5b14dc32bf656ef6c6bd58a5d943f92",
			secret: "005543894af3d00ed7d740abdbd75c96b06877b787db5f70eea78b90a8d7c00a",
		},
		{
			name: "P-384", curve: ecdh.P384(), legacy: elliptic.P384(), algorithm: protocol.ECCP384,
			point:  "04004d104b26ee5671f72c10c986841d3e65d285e2516161b7baa341b12631b9e32b6f0d5896d8431c51d5d93a37cbc90ef11a1e3f8b7b90538ee42cc00ee934a6e2ee25541607d8fb65c7a8b11e2f886853886eef3865ec933200b9f25599f29f",
			secret: "004d104b26ee5671f72c10c986841d3e65d285e2516161b7baa341b12631b9e32b6f0d5896d8431c51d5d93a37cbc90e",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			point, err := hex.DecodeString(tc.point)
			if err != nil {
				t.Fatal(err)
			}

			peer, err := tc.curve.NewPublicKey(point)
			if err != nil {
				t.Fatal(err)
			}

			want, err := hex.DecodeString(tc.secret)
			if err != nil {
				t.Fatal(err)
			}

			private := ecdhScalar(t, tc.curve, 1)

			oracle, err := private.ECDH(peer)
			if err != nil || !bytes.Equal(oracle, want) {
				t.Fatalf("fixed ECDH vector = %x, %v; want %x", oracle, err, want)
			}

			public, err := ecdsa.ParseUncompressedPublicKey(tc.legacy, private.PublicKey().Bytes())
			if err != nil {
				t.Fatal(err)
			}

			device, _ := newDevice(t, exchangeStep{
				command: ecdhCommand(tc.algorithm, protocol.KeyManagement, peer), response: ecdhResponse(want),
			})
			key := bindECDH(t, device, protocol.KeyManagement, public)

			got, err := key.ECDH(t.Context(), peer, nil)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("ECDH = %x, %v; want full-width %x", got, err, want)
			}
		})
	}
}

func TestECDHRejectsUnsupportedInputsBeforeAuthentication(t *testing.T) {
	public, peer, _ := ecdhMaterial(t, ecdh.P256())
	_, otherCurve, _ := ecdhMaterial(t, ecdh.P384())
	x25519 := ecdhScalar(t, ecdh.X25519(), 9).PublicKey()

	for _, tc := range []struct {
		name      string
		reference protocol.KeyReference
		peer      *ecdh.PublicKey
		rsa       bool
	}{
		{name: "authentication slot", reference: protocol.PIVAuthentication, peer: peer},
		{name: "signature slot", reference: protocol.DigitalSignature, peer: peer},
		{name: "card authentication slot", reference: protocol.CardAuthentication, peer: peer},
		{name: "RSA key", reference: protocol.KeyManagement, peer: peer, rsa: true},
		{name: "different curve", reference: protocol.KeyManagement, peer: otherCurve},
		{name: "X25519 peer", reference: protocol.KeyManagement, peer: x25519},
	} {
		t.Run(tc.name, func(t *testing.T) {
			device, _ := newDevice(t)

			key := bindECDH(t, device, tc.reference, public)
			if tc.rsa {
				var err error

				key, err = device.PrivateKey(tc.reference, &signingRSA(t).PublicKey)
				if err != nil {
					t.Fatal(err)
				}
			}

			calls := 0
			authentication := func(context.Context) (protocol.VerifyRequest, error) {
				calls++
				return protocol.VerifyRequest{}, nil
			}

			secret, err := key.ECDH(t.Context(), tc.peer, authentication)
			if err == nil || secret != nil || calls != 0 {
				t.Fatalf("ECDH = %x, %v; authentication calls=%d", secret, err, calls)
			}
		})
	}
}

func TestECDHRejectsMalformedResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "missing template"},
		{name: "malformed template", data: []byte{0x7c, 1}},
		{name: "missing response", data: []byte{0x7c, 0}},
		{name: "empty response", data: []byte{0x7c, 2, 0x82, 0}},
		{name: "short response", data: ecdhResponse(make([]byte, 31)).Data},
		{name: "long response", data: ecdhResponse(make([]byte, 33)).Data},
		{name: "unexpected witness", data: append([]byte{0x7c, 36, 0x80, 0, 0x82, 32}, make([]byte, 32)...)},
		{name: "unexpected challenge", data: append([]byte{0x7c, 36, 0x81, 0, 0x82, 32}, make([]byte, 32)...)},
		{name: "unexpected exponentiation", data: append([]byte{0x7c, 36, 0x85, 0, 0x82, 32}, make([]byte, 32)...)},
		{name: "duplicate response", data: []byte{0x7c, 4, 0x82, 0, 0x82, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			public, peer, _ := ecdhMaterial(t, ecdh.P256())
			device, raw := newDevice(t,
				exchangeStep{command: ecdhCommand(protocol.ECCP256, protocol.KeyManagement, peer), response: iso7816.Response{Status: 0x9000, Data: tc.data}},
				exchangeStep{command: []byte{0, 0xfd, 0, 0}, response: iso7816.Response{Status: 0x9000}},
			)
			key := bindECDH(t, device, protocol.KeyManagement, public)

			secret, err := key.ECDH(t.Context(), peer, nil)
			if secret != nil || !errors.Is(err, protocol.ErrInvalidResponse) {
				t.Fatalf("ECDH = %x, %v; want invalid response", secret, err)
			}

			if _, err := device.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); err != nil || raw.closeCalls != 0 {
				t.Fatalf("completed malformed ECDH invalidated the connection: %v, closes=%d", err, raw.closeCalls)
			}
		})
	}
}

func TestECDHAuthenticationOwnership(t *testing.T) {
	for _, outcome := range []string{"success", "VERIFY rejected", "GA rejected", "source failed"} {
		t.Run(outcome, func(t *testing.T) {
			public, peer, want := ecdhMaterial(t, ecdh.P256())
			data := []byte{0x10, 0x80, 0xff}
			cause := errors.New("biometric acquisition canceled")

			var steps []exchangeStep

			if outcome != "source failed" {
				status := iso7816.StatusWord(0x9000)
				if outcome == "VERIFY rejected" {
					status = 0x63c2
				}

				steps = append(steps, exchangeStep{
					command: []byte{0, 0x20, 0, byte(protocol.PrimaryFingerOCC), 3, 0x10, 0x80, 0xff}, response: iso7816.Response{Status: status},
				})
				if outcome != "VERIFY rejected" {
					response := ecdhResponse(want)
					if outcome == "GA rejected" {
						response = iso7816.Response{Status: 0x6982}
					}

					steps = append(steps, exchangeStep{command: ecdhCommand(protocol.ECCP256, protocol.KeyManagement, peer), response: response})
				}
			}

			device, raw := newDevice(t, steps...)
			key := bindECDH(t, device, protocol.KeyManagement, public)
			authentication := func(ctx context.Context) (protocol.VerifyRequest, error) {
				if ctx != t.Context() {
					t.Error("authentication source received a substituted context")
				}

				request := protocol.VerifyRequest{Reference: protocol.PrimaryFingerOCC, Data: data}
				if outcome == "source failed" {
					return request, cause
				}

				return request, nil
			}

			secret, err := key.ECDH(t.Context(), peer, authentication)

			switch outcome {
			case "success":
				if err != nil || !bytes.Equal(secret, want) {
					t.Fatalf("ECDH = %x, %v; want %x", secret, err, want)
				}
			case "VERIFY rejected":
				var referenceError *client.ReferenceDataError
				if secret != nil || !errors.As(err, &referenceError) || referenceError.Reference != protocol.PrimaryFingerOCC || referenceError.Retries != 2 {
					t.Fatalf("ECDH = %x, %v; want OCC error with two retries", secret, err)
				}
			case "GA rejected":
				var apduError *iso7816.APDUError
				if secret != nil || !errors.As(err, &apduError) || apduError.SW1 != 0x69 || apduError.SW2 != 0x82 {
					t.Fatalf("ECDH = %x, %v; want GA security-status error", secret, err)
				}
			case "source failed":
				if secret != nil || !errors.Is(err, cause) {
					t.Fatalf("ECDH = %x, %v; want acquisition error", secret, err)
				}
			}

			wantData := make([]byte, len(data))
			if outcome == "source failed" {
				wantData = []byte{0x10, 0x80, 0xff}
			}

			if !bytes.Equal(data, wantData) || raw.closeCalls != 0 {
				t.Errorf("authentication data = %x, want %x; closes=%d", data, wantData, raw.closeCalls)
			}
		})
	}
}

func TestECDHAuthenticationRunsBeforeGate(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		public, peer, want := ecdhMaterial(t, ecdh.P256())
		device, _ := newDevice(t,
			exchangeStep{command: []byte{0, 0x20, 0, 0}, response: iso7816.Response{Status: 0x9000}},
			exchangeStep{command: []byte{0, 0x20, 0, 0}, response: iso7816.Response{Status: 0x9000}},
			exchangeStep{command: ecdhCommand(protocol.ECCP256, protocol.KeyManagement, peer), response: ecdhResponse(want)},
		)
		key := bindECDH(t, device, protocol.KeyManagement, public)
		authentication := func(ctx context.Context) (protocol.VerifyRequest, error) {
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()

			if _, err := device.ReferenceStatus(ctx, protocol.GlobalPIN); err != nil {
				return protocol.VerifyRequest{}, err
			}

			return protocol.VerifyRequest{Reference: protocol.GlobalPIN}, nil
		}

		if _, err := key.ECDH(t.Context(), peer, authentication); err != nil {
			t.Fatal(err)
		}
	})
}

func TestECDHAuthenticationAndOperationExcludeVendorExchange(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		public, peer, want := ecdhMaterial(t, ecdh.P256())
		verified, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		device, raw := newDevice(t,
			exchangeStep{
				command: []byte{0, 0x20, 0, 0}, response: iso7816.Response{Status: 0x9000},
				after: func() { close(verified); <-proceed },
			},
			exchangeStep{command: ecdhCommand(protocol.ECCP256, protocol.KeyManagement, peer), response: ecdhResponse(want)},
			exchangeStep{command: []byte{0, 0xfd, 0, 0}, response: iso7816.Response{Status: 0x9000}},
		)
		key := bindECDH(t, device, protocol.KeyManagement, public)
		completed := make(chan error, 1)

		go func() {
			_, err := key.ECDH(t.Context(), peer, func(context.Context) (protocol.VerifyRequest, error) {
				return protocol.VerifyRequest{Reference: protocol.GlobalPIN}, nil
			})
			completed <- err
		}()

		receive(t, verified, "ECDH authentication did not start")

		vendor := make(chan error, 1)

		go func() { _, err := device.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); vendor <- err }()

		synctest.Wait()

		if raw.calls != 1 {
			t.Fatalf("exchanges before ECDH = %d, want VERIFY only", raw.calls)
		}

		release()

		if err := receive(t, completed, "ECDH did not finish"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, vendor, "vendor exchange did not finish"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestQueuedECDHCancellationClearsAuthenticationData(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		public, peer, want := ecdhMaterial(t, ecdh.P256())
		started, proceed := make(chan struct{}), make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		device, raw := newDevice(t,
			exchangeStep{
				command: []byte{0, 0xfd, 0, 0}, response: iso7816.Response{Status: 0x9000},
				after: func() { close(started); <-proceed },
			},
			exchangeStep{command: ecdhCommand(protocol.ECCP256, protocol.KeyManagement, peer), response: ecdhResponse(want)},
		)
		key := bindECDH(t, device, protocol.KeyManagement, public)
		active := make(chan error, 1)

		go func() { _, err := device.Exchange(t.Context(), iso7816.Command{INS: 0xfd}); active <- err }()

		receive(t, started, "active operation did not start")

		data := []byte{0x10, 0x80, 0xff}
		sourced := make(chan struct{})

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		queued := make(chan error, 1)

		go func() {
			_, err := key.ECDH(ctx, peer, func(context.Context) (protocol.VerifyRequest, error) {
				close(sourced)
				return protocol.VerifyRequest{Reference: protocol.PrimaryFingerOCC, Data: data}, nil
			})
			queued <- err
		}()

		receive(t, sourced, "queued ECDH did not obtain authentication data")
		synctest.Wait()
		cancel()

		if err := receive(t, queued, "queued ECDH ignored cancellation"); !errors.Is(err, context.Canceled) {
			t.Fatalf("ECDH = %v, want cancellation", err)
		}

		if !bytes.Equal(data, make([]byte, len(data))) || raw.calls != 1 || raw.closeCalls != 0 {
			t.Fatalf("queued cancellation retained data or changed the session: data=%x calls/closes=%d/%d", data, raw.calls, raw.closeCalls)
		}

		release()

		if err := receive(t, active, "active operation did not finish"); err != nil {
			t.Fatal(err)
		}

		if _, err := key.ECDH(t.Context(), peer, nil); err != nil {
			t.Fatalf("ECDH after queued cancellation = %v", err)
		}
	})
}

func TestECDHCanceledBeforeStartDoesNotAuthenticate(t *testing.T) {
	public, peer, _ := ecdhMaterial(t, ecdh.P256())
	device, _ := newDevice(t)
	key := bindECDH(t, device, protocol.KeyManagement, public)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	calls := 0

	secret, err := key.ECDH(ctx, peer, func(context.Context) (protocol.VerifyRequest, error) {
		calls++
		return protocol.VerifyRequest{}, nil
	})
	if secret != nil || !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("ECDH = %x, %v; source calls=%d", secret, err, calls)
	}
}

func TestECDHPreservesCompletedResultAfterCancellation(t *testing.T) {
	public, peer, want := ecdhMaterial(t, ecdh.P256())

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	device, raw := newDevice(t, exchangeStep{
		command: ecdhCommand(protocol.ECCP256, protocol.KeyManagement, peer), response: ecdhResponse(want), after: cancel,
	})
	key := bindECDH(t, device, protocol.KeyManagement, public)

	secret, err := key.ECDH(ctx, peer, nil)
	if err != nil || !bytes.Equal(secret, want) || raw.closeCalls != 0 {
		t.Fatalf("completed ECDH = %x, %v; closes=%d", secret, err, raw.closeCalls)
	}
}

type blockingECDHTransport struct {
	started chan struct{}
	closed  chan struct{}
}

func (b *blockingECDHTransport) Exchange(context.Context, iso7816.Command) (iso7816.Response, error) {
	close(b.started)
	<-b.closed

	return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: io.ErrClosedPipe}
}

func (b *blockingECDHTransport) Close() error {
	close(b.closed)
	return nil
}

func TestCloseInterruptsECDHIO(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		public, peer, _ := ecdhMaterial(t, ecdh.P256())
		raw := &blockingECDHTransport{started: make(chan struct{}), closed: make(chan struct{})}
		device := New(raw)

		t.Cleanup(func() { _ = device.Close() })
		key := bindECDH(t, device, protocol.KeyManagement, public)
		completed := make(chan error, 1)

		go func() { _, err := key.ECDH(t.Context(), peer, nil); completed <- err }()

		receive(t, raw.started, "ECDH I/O did not start")

		if err := device.Close(); err != nil {
			t.Fatal(err)
		}

		var invalidated *transport.DeviceInvalidatedError
		if err := receive(t, completed, "Close did not interrupt ECDH I/O"); !errors.As(err, &invalidated) || !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("interrupted ECDH = %v, want invalidated closed connection", err)
		}

		if _, err := key.ECDH(t.Context(), peer, nil); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("ECDH after Close = %v", err)
		}
	})
}
