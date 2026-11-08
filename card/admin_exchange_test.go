package card

import (
	"bytes"
	"context"
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

func TestExchangeAdministrationAuthenticatesAndPreservesRawExchange(t *testing.T) {
	d, raw := newAdministrationPeer(t, administrationVectors[0])
	command := iso7816.Command{CLA: 0x80, INS: 0xf8, P1: 1, P2: 2, Data: []byte{3, 4}, Le: 256}
	want := []byte{0x80, 0xf8, 1, 2, 2, 3, 4, 0}
	raw.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		encoded, err := command.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(encoded, want) {
			t.Errorf("command = %x, want %x", encoded, want)
		}

		return iso7816.Response{Status: 0x6982, Data: []byte{5, 6}}, nil
	}
	originalKey := bytes.Clone(raw.key.Key)

	for range 2 {
		response, err := d.ExchangeAdministration(t.Context(), command, raw.key, nil)
		if err != nil {
			t.Fatal(err)
		}

		if response.Status != 0x6982 || !bytes.Equal(response.Data, []byte{5, 6}) {
			t.Errorf("response = %+v, want status 6982 and data 0506", response)
		}
	}

	if raw.authentications != 2 || raw.effects != 2 || len(raw.requests) != 6 {
		t.Errorf("authentications=%d effects=%d APDUs=%d, want 2, 2, 6", raw.authentications, raw.effects, len(raw.requests))
	}

	if !bytes.Equal(raw.key.Key, originalKey) || !bytes.Equal(command.Data, []byte{3, 4}) {
		t.Error("borrowed key or command data was changed")
	}

	if raw.closeCalls != 0 {
		t.Error("raw APDU rejection closed the session")
	}
}

func TestExchangeAdministrationAuthenticatesSourceOutsideGateAndVerifiesBeforeCommand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, raw := newAdministrationPeer(t, administrationVectors[0])
		data := []byte{1, 2, 3, 4, 5, 6, 0xff, 0xff}
		command := iso7816.Command{INS: 0xf8}
		raw.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
			return iso7816.Response{Status: 0x9000}, nil
		}
		authentication := func(ctx context.Context) (protocol.VerifyRequest, error) {
			ctx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()

			if _, err := d.Exchange(ctx, iso7816.Command{INS: 0xfd}); err != nil {
				return protocol.VerifyRequest{}, err
			}

			return protocol.VerifyRequest{Reference: protocol.GlobalPIN, Data: data}, nil
		}

		if _, err := d.ExchangeAdministration(t.Context(), command, raw.key, authentication); err != nil {
			t.Fatal(err)
		}

		if len(raw.requests) != 5 {
			t.Fatalf("APDU count = %d, want 5", len(raw.requests))
		}

		if raw.requests[0][1] != 0xfd || raw.requests[1][1] != 0x87 || raw.requests[2][1] != 0x87 ||
			!bytes.Equal(raw.requests[3], []byte{0, 0x20, 0, 0, 8, 1, 2, 3, 4, 5, 6, 0xff, 0xff}) ||
			!bytes.Equal(raw.requests[4], []byte{0, 0xf8, 0, 0}) {
			t.Errorf("unexpected source/authentication/VERIFY/command order: %x", raw.requests)
		}

		if !bytes.Equal(data, make([]byte, len(data))) {
			t.Error("owned authentication data was not cleared")
		}
	})
}

func TestExchangeAdministrationStopsAfterPINFailure(t *testing.T) {
	d, raw := newAdministrationPeer(t, administrationVectors[0])
	raw.effect = func(_ context.Context, command iso7816.Command) (iso7816.Response, error) {
		if command.INS != byte(protocol.Verify) {
			t.Errorf("command after failed VERIFY = %02x", command.INS)
		}

		return iso7816.Response{Status: 0x63c2}, nil
	}
	data := []byte{1, 2, 3, 4, 5, 6, 0xff, 0xff}
	authentication := func(context.Context) (protocol.VerifyRequest, error) {
		return protocol.VerifyRequest{Reference: protocol.ApplicationPIN, Data: data}, nil
	}

	_, err := d.ExchangeAdministration(t.Context(), iso7816.Command{INS: 0xf8}, raw.key, authentication)

	var pinError *client.ReferenceDataError
	if !errors.As(err, &pinError) || pinError.Retries != 2 || pinError.Reference != protocol.ApplicationPIN {
		t.Fatalf("ExchangeAdministration = %v, want PIN failure with two retries", err)
	}

	if raw.effects != 1 || len(raw.requests) != 3 || raw.closeCalls != 0 {
		t.Errorf("effects=%d APDUs=%d closes=%d, want 1, 3, 0", raw.effects, len(raw.requests), raw.closeCalls)
	}

	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Error("failed VERIFY authentication data was not cleared")
	}
}

func TestExchangeAdministrationRejectsInvalidKeyBeforeSourceAndIO(t *testing.T) {
	d, raw := newDevice(t)
	authentication := func(context.Context) (protocol.VerifyRequest, error) {
		t.Error("authentication source ran with invalid management key")
		return protocol.VerifyRequest{}, nil
	}

	_, err := d.ExchangeAdministration(t.Context(), iso7816.Command{INS: 0xf8}, AdministrationKey{Algorithm: protocol.AES128, Key: []byte{1}}, authentication)

	if err == nil || raw.calls != 0 {
		t.Errorf("ExchangeAdministration = %v, APDUs=%d; want key error without I/O", err, raw.calls)
	}
}

func TestExchangeAdministrationStopsAfterRejectedManagementAuthentication(t *testing.T) {
	d, raw := newAdministrationPeer(t, administrationVectors[0])
	raw.reject = 1

	_, err := d.ExchangeAdministration(t.Context(), iso7816.Command{INS: 0xf8}, raw.key, nil)

	var apdu *iso7816.APDUError
	if !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
		t.Fatalf("ExchangeAdministration = %v, want APDU rejection 6982", err)
	}

	if raw.effects != 0 || len(raw.requests) != 1 || raw.closeCalls != 0 {
		t.Errorf("effects=%d APDUs=%d closes=%d, want 0, 1, 0", raw.effects, len(raw.requests), raw.closeCalls)
	}
}

func TestExchangeAdministrationInvalidationClosesSession(t *testing.T) {
	for _, phase := range []string{"management proof", "vendor command"} {
		t.Run(phase, func(t *testing.T) {
			d, raw := newAdministrationPeer(t, administrationVectors[0])
			cause := errors.New("card removed")
			closeErr := errors.New("disconnect failed")

			raw.closeErr = closeErr
			if phase == "management proof" {
				raw.proofReply = func(proof []byte) iso7816.Response {
					proof[0] ^= 1
					return administrationReply(0x82, proof)
				}
				cause = ErrAdministrationAuthentication
			} else {
				raw.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
					return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: cause}
				}
			}

			_, err := d.ExchangeAdministration(t.Context(), iso7816.Command{INS: 0xf8}, raw.key, nil)

			var invalidated *transport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) || !errors.Is(err, cause) || !errors.Is(err, closeErr) {
				t.Fatalf("ExchangeAdministration = %v, want invalidation and both causes", err)
			}

			if raw.closeCalls != 1 {
				t.Errorf("close count = %d, want 1", raw.closeCalls)
			}

			if _, err := d.ExchangeAdministration(t.Context(), iso7816.Command{INS: 0xf8}, raw.key, nil); !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("ExchangeAdministration after invalidation = %v, want ErrClosedPipe", err)
			}
		})
	}
}

func TestExchangeAdministrationHoldsGateAcrossAuthenticationAndCommand(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		d, raw := newAdministrationPeer(t, administrationVectors[0])
		started := make(chan struct{})
		proceed := make(chan struct{})

		release := sync.OnceFunc(func() { close(proceed) })
		defer release()

		raw.afterWitness = func() { close(started); <-proceed }
		raw.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
			return iso7816.Response{Status: 0x9000}, nil
		}
		first := make(chan error, 1)

		go func() {
			_, err := d.ExchangeAdministration(t.Context(), iso7816.Command{INS: 0xf8}, raw.key, nil)
			first <- err
		}()

		receive(t, started, "management authentication did not start")

		second := make(chan error, 1)

		go func() {
			_, err := d.Exchange(t.Context(), iso7816.Command{INS: 0xfd})
			second <- err
		}()

		synctest.Wait()

		if len(raw.requests) != 1 {
			t.Fatalf("APDUs while authentication is active = %d, want 1", len(raw.requests))
		}

		release()

		if err := receive(t, first, "administrative exchange did not finish"); err != nil {
			t.Fatal(err)
		}

		if err := receive(t, second, "queued exchange did not finish"); err != nil {
			t.Fatal(err)
		}

		if len(raw.requests) != 4 || raw.requests[2][1] != 0xf8 || raw.requests[3][1] != 0xfd {
			t.Errorf("administration and queued command order = %x", raw.requests)
		}
	})
}

func TestExchangeAdministrationCancellationClearsAuthenticationAndPreservesSession(t *testing.T) {
	for _, phase := range []string{"source", "witness", "proof"} {
		t.Run(phase, func(t *testing.T) {
			d, raw := newAdministrationPeer(t, administrationVectors[0])

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			switch phase {
			case "witness":
				raw.afterWitness = cancel
			case "proof":
				raw.afterProof = cancel
			}

			data := []byte{1, 2, 3, 4, 5, 6, 0xff, 0xff}
			authentication := func(context.Context) (protocol.VerifyRequest, error) {
				if phase == "source" {
					cancel()
				}

				return protocol.VerifyRequest{Reference: protocol.ApplicationPIN, Data: data}, nil
			}

			_, err := d.ExchangeAdministration(ctx, iso7816.Command{INS: 0xf8}, raw.key, authentication)

			if !errors.Is(err, context.Canceled) || raw.effects != 0 || raw.closeCalls != 0 {
				t.Fatalf("canceled exchange = %v, effects=%d closes=%d", err, raw.effects, raw.closeCalls)
			}

			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("canceled authentication data was not cleared")
			}

			raw.afterWitness, raw.afterProof = nil, nil
			raw.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
				return iso7816.Response{Status: 0x9000}, nil
			}

			if _, err := d.ExchangeAdministration(t.Context(), iso7816.Command{INS: 0xf8}, raw.key, nil); err != nil {
				t.Fatalf("fresh workflow after cancellation = %v", err)
			}
		})
	}
}
