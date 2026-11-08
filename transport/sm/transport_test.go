package sm

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestAuthenticatedErrorPreservesSession(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		p := newHandshakePeer(t, suite)
		channel := openHandshakePeer(t, p)
		p.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
			return p.protectedResponse(nil, 0x63c3), nil
		}

		response, err := channel.Exchange(t.Context(), iso7816.Command{INS: 0x20, P2: 0x80})
		if err != nil || response.Status != 0x63c3 || len(response.Data) != 0 || !channel.PIVSecureMessaging() {
			t.Fatalf("authenticated failure = %+v, %v", response, err)
		}

		p.effect = nil

		if _, err := channel.Exchange(t.Context(), readCommand()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestExchangeInvalidatesAndClears(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		for _, mode := range []string{"bare status", "bad MAC", "I/O", "interrupted", "exhausted"} {
			t.Run(mode, func(t *testing.T) {
				p := newHandshakePeer(t, suite)
				channel := openHandshakePeer(t, p)
				cause := errors.New("lost response")
				p.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
					switch mode {
					case "bare status":
						return iso7816.Response{Status: 0x6988}, nil
					case "bad MAC":
						r := p.protectedResponse([]byte("unverified"), 0x9000)
						r.Data[len(r.Data)-1] ^= 1

						return r, nil
					case "interrupted":
						return iso7816.Response{}, &transport.DeviceInvalidatedError{Err: context.Canceled}
					default:
						return iso7816.Response{}, cause
					}
				}

				if mode == "exhausted" {
					channel.session.counter = [16]byte{}
				}

				response, err := channel.Exchange(t.Context(), readCommand())

				var invalidated *transport.DeviceInvalidatedError
				if !errors.As(err, &invalidated) || len(response.Data) != 0 || p.closeCalls != 1 {
					t.Fatalf("Exchange = %+v, %v, closes=%d", response, err, p.closeCalls)
				}

				if channel.PIVSecureMessaging() || channel.session.keys != (sessionKeys{}) {
					t.Fatal("invalidated session retained keys or remained open")
				}

				calls := len(p.requests)
				if _, err := channel.Exchange(t.Context(), readCommand()); !errors.Is(err, io.ErrClosedPipe) || len(p.requests) != calls {
					t.Fatalf("Exchange after invalidation = %v", err)
				}
			})
		}
	})
}

func TestCancellationBeforeIOPreservesState(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		p := newHandshakePeer(t, suite)
		channel := openHandshakePeer(t, p)
		ctx, cancel := context.WithCancel(t.Context())
		p.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
			cancel()
			return iso7816.Response{}, ctx.Err()
		}

		before := channel.session
		if _, err := channel.Exchange(ctx, readCommand()); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}

		if channel.session != before || p.closeCalls != 0 {
			t.Fatal("pre-I/O cancellation changed state")
		}

		p.effect = nil

		if _, err := channel.Exchange(t.Context(), readCommand()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestCompletedResponseSurvivesCancellation(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		p := newHandshakePeer(t, suite)
		channel := openHandshakePeer(t, p)
		ctx, cancel := context.WithCancel(t.Context())
		p.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
			r := p.protectedResponse([]byte("completed"), 0x9000)

			cancel()

			return r, nil
		}

		r, err := channel.Exchange(ctx, readCommand())
		if err != nil || string(r.Data) != "completed" {
			t.Fatalf("Exchange = %+v, %v", r, err)
		}
	})
}

func TestCloseInterruptsIOAndReleasesWaiters(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		synctest.Test(t, func(t *testing.T) {
			p := newHandshakePeer(t, suite)
			channel := openHandshakePeer(t, p)
			ctx, cancel := context.WithCancel(t.Context())

			var workers sync.WaitGroup

			defer func() {
				cancel()

				done := make(chan struct{})

				go func() {
					_ = channel.Close()

					workers.Wait()
					close(done)
				}()

				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("workers did not stop after cleanup")
				}
			}()

			p.effect = func(ctx context.Context, _ iso7816.Command) (iso7816.Response, error) {
				select {
				case <-p.closed:
					return iso7816.Response{}, io.ErrClosedPipe
				case <-ctx.Done():
					return iso7816.Response{}, ctx.Err()
				}
			}
			active := make(chan error, 1)

			workers.Go(func() { _, err := channel.Exchange(ctx, readCommand()); active <- err })

			synctest.Wait()

			if len(p.requests) != 3 {
				t.Fatalf("active Exchange did not reach I/O: requests=%d, want 3", len(p.requests))
			}

			select {
			case err := <-active:
				t.Fatalf("active Exchange completed before Close: %v", err)
			default:
			}

			queued := make(chan error, 1)

			workers.Go(func() { _, err := channel.Exchange(ctx, readCommand()); queued <- err })

			synctest.Wait()

			select {
			case err := <-queued:
				t.Fatalf("queued Exchange completed before Close: %v", err)
			default:
			}

			if len(p.requests) != 3 {
				t.Fatalf("queued Exchange performed I/O: requests=%d, want 3", len(p.requests))
			}

			closed := make(chan error, 1)

			workers.Go(func() { closed <- channel.Close() })

			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close waited for the active exchange")
			}

			synctest.Wait()

			for _, caller := range []struct {
				name   string
				result <-chan error
			}{
				{name: "queued", result: queued},
				{name: "active", result: active},
			} {
				select {
				case err := <-caller.result:
					if !errors.Is(err, io.ErrClosedPipe) {
						t.Fatalf("%s Exchange after Close = %v, want closed pipe", caller.name, err)
					}
				case <-time.After(time.Second):
					t.Fatalf("%s Exchange did not stop after Close", caller.name)
				}
			}

			if p.closeCalls != 1 || len(p.requests) != 3 || channel.session.keys != (sessionKeys{}) {
				t.Fatal("close did not retire session once")
			}
		})
	})
}

func TestCloseErrorAndLocalRejection(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		p := newHandshakePeer(t, suite)

		channel := openHandshakePeer(t, p)
		if _, err := channel.Exchange(t.Context(), protocol.SelectCommand()); !errors.Is(err, iso7816.ErrInvalidCommand) {
			t.Fatal(err)
		}

		if len(p.requests) != 2 || !channel.PIVSecureMessaging() {
			t.Fatal("local rejection performed I/O or invalidated")
		}

		p.closeErr = errors.New("close failed")
		for range 2 {
			if err := channel.Close(); !errors.Is(err, p.closeErr) {
				t.Fatal(err)
			}
		}

		if p.closeCalls != 1 || channel.session.keys != (sessionKeys{}) {
			t.Fatal("close repeated or retained keys")
		}
	})
}

func TestExchangeRejectsOversizedProtectedDataBeforeIO(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		p := newHandshakePeer(t, suite)
		parameters := p.parameters()
		parameters.Encoding = iso7816.EncodingExtended

		channel, err := Open(t.Context(), p, parameters)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = channel.Close() })

		before := channel.session
		calls := len(p.requests)
		command := iso7816.Command{INS: 0x87, P1: 0x11, P2: 0x9c, Data: make([]byte, 65504), Le: 256}

		response, err := channel.Exchange(t.Context(), command)
		if !errors.Is(err, iso7816.ErrInvalidCommand) || response.Data != nil || response.Status != 0 {
			t.Errorf("oversized protected Exchange = %+v, %v; want invalid command", response, err)
		}

		if len(p.requests) != calls || p.closeCalls != 0 || channel.session != before || !channel.PIVSecureMessaging() {
			t.Fatal("local size rejection performed I/O or changed the session")
		}

		if _, err := channel.Exchange(t.Context(), readCommand()); err != nil {
			t.Fatalf("Exchange after local size rejection: %v", err)
		}

		if len(p.requests) != calls+1 {
			t.Errorf("Exchange count after reuse = %d, want %d", len(p.requests), calls+1)
		}
	})
}
