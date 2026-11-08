package sm

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"testing/synctest"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

type handshakePeer struct {
	t             testing.TB
	suite         cipherSuite
	static        *ecdh.PrivateKey
	signer        *ecdsa.PrivateKey
	issuer        [8]byte
	certificate   []byte
	keys          sessionKeys
	counter       [16]byte
	responseChain [16]byte
	requests      []iso7816.Command
	handshake     func(iso7816.Response) iso7816.Response
	effect        func(context.Context, iso7816.Command) (iso7816.Response, error)
	application   []byte
	closed        chan struct{}
	closeOnce     sync.Once
	closeCalls    int
	closeErr      error
}

func newHandshakePeer(t testing.TB, suite cipherSuite) *handshakePeer {
	t.Helper()

	static, err := suite.curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ecdsa.GenerateKey(suite.signingCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &handshakePeer{
		t: t, suite: suite, static: static, signer: signer, issuer: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		counter: [16]byte{15: 1}, closed: make(chan struct{}),
	}
	p.certificate = fixtureCertificate(t, static.PublicKey(), signer, p.issuer)
	p.application = bertlv.Append(nil, 0x61, []byte{
		0x4f, 1, 1, 0x79, 3, 0x4f, 1, 2,
		0xac, 6, 0x80, 1, byte(suite.algorithm), 6, 1, 0,
	})

	return p
}

func (p *handshakePeer) parameters() Parameters {
	return Parameters{
		CipherSuite: p.suite.algorithm,
		Trust:       Trust{IssuerID: p.issuer, PublicKey: &p.signer.PublicKey},
		HostID:      [8]byte{8, 7, 6, 5, 4, 3, 2, 1}, Encoding: iso7816.EncodingShort,
	}
}

func (p *handshakePeer) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	if err := ctx.Err(); err != nil {
		return iso7816.Response{}, err
	}

	copy := command
	copy.Data = slices.Clone(command.Data)

	p.requests = append(p.requests, copy)
	if command.INS == 0xa4 {
		return iso7816.Response{Data: p.application, Status: 0x9000}, nil
	}

	if command.CLA == 0 && command.INS == 0x87 {
		p.t.Helper()

		if command.P1 != byte(p.suite.algorithm) || command.P2 != 4 || command.Encoding != iso7816.EncodingShort || command.Le != 256 {
			p.t.Fatalf("establishment command = %+v", command)
		}

		body, err := protocol.ParseObject(command.Data, 0x7c)
		if err != nil {
			p.t.Fatal(err)
		}

		tag, challenge, rest, err := bertlv.Parse(body)
		if err != nil || tag != 0x81 || len(challenge) != 9+len(p.static.PublicKey().Bytes()) || challenge[0] != 0 || !bytes.Equal(rest, []byte{0x82, 0}) {
			p.t.Fatalf("establishment data = %x, %v", body, err)
		}

		hostID := [8]byte(challenge[1:9])
		public := challenge[9:]

		key, err := p.suite.curve.NewPublicKey(public)
		if err != nil {
			p.t.Fatal(err)
		}

		z, err := p.static.ECDH(key)
		if err != nil {
			p.t.Fatal(err)
		}
		defer clear(z)

		nonce := bytes.Repeat([]byte{0x42}, p.suite.nonceSize)
		id := sha256.Sum256(p.certificate)
		p.keys = deriveKeys(p.suite, z, hostID, [8]byte(id[:8]), public, nonce)
		confirmation := append([]byte("KC_1_V"), id[:8]...)
		confirmation = append(confirmation, hostID[:]...)
		confirmation = append(confirmation, public[1:]...)
		cryptogram := cmac(p.keys.cfrm[:p.keys.keySize], confirmation)

		data := append([]byte{0}, nonce...)
		data = append(data, cryptogram[:]...)
		data = append(data, p.certificate...)

		response := iso7816.Response{Data: bertlv.Append(nil, 0x7c, bertlv.Append(nil, 0x82, data)), Status: 0x9000}
		if p.handshake != nil {
			response = p.handshake(response)
		}

		return response, nil
	}

	if p.effect != nil {
		return p.effect(ctx, command)
	}

	return p.protectedResponse([]byte("public object"), 0x9000), nil
}

func (p *handshakePeer) protectedResponse(plaintext []byte, status iso7816.StatusWord) iso7816.Response {
	var data []byte

	if len(plaintext) != 0 {
		counter := p.counter
		counter[0] = 0x80
		data = bertlv.Append(nil, 0x87, append([]byte{1}, encrypt(p.keys.enc[:p.keys.keySize], counter, plaintext)...))
	}

	data = append(data, 0x99, 2, status.SW1(), status.SW2())
	mac := cmac(p.keys.rmac[:p.keys.keySize], append(p.responseChain[:], data...))
	data = bertlv.Append(data, 0x8e, mac[:8])
	p.responseChain = mac
	p.counter[15]++

	return iso7816.Response{Data: data, Status: 0x9000}
}

func (p *handshakePeer) Close() error {
	p.closeCalls++
	p.closeOnce.Do(func() { close(p.closed) })

	return p.closeErr
}

func openHandshakePeer(t testing.TB, p *handshakePeer) *Transport {
	t.Helper()

	channel, err := Open(t.Context(), p, p.parameters())
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = channel.Close() })

	return channel
}

func readCommand() iso7816.Command {
	return iso7816.Command{INS: 0xcb, P1: 0x3f, P2: 0xff, Data: []byte{0x5c, 1, 0x7e}, Le: 256}
}

func TestOpenAndSequentialExchanges(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		for _, encoding := range []iso7816.Encoding{iso7816.EncodingShort, iso7816.EncodingExtended} {
			p := newHandshakePeer(t, suite)
			parameters := p.parameters()
			parameters.Encoding = encoding

			channel, err := Open(t.Context(), p, parameters)
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = channel.Close() })

			for range 3 {
				response, err := channel.Exchange(t.Context(), readCommand())
				if err != nil || response.Status != 0x9000 || string(response.Data) != "public object" {
					t.Fatalf("Exchange = %+v, %v", response, err)
				}
			}

			if !channel.PIVSecureMessaging() || channel.session.counter[15] != 4 {
				t.Fatal("session not active or counter did not advance")
			}

			if channel.session.keys.cfrm != [32]byte{} {
				t.Fatal("key confirmation key retained in session")
			}

			if len(p.requests) != 5 || p.requests[0].INS != 0xa4 || p.requests[1].INS != 0x87 || p.requests[2].CLA != 0x0c {
				t.Fatalf("requests = %+v", p.requests)
			}

			if p.requests[2].Encoding != encoding || channel.session.keys.keySize != suite.keySize {
				t.Fatalf("protected encoding/key size = %v/%d", p.requests[2].Encoding, channel.session.keys.keySize)
			}
		}
	})
}

func TestFailedOpenOwnership(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		for _, mode := range []string{"encoding", "missing suite", "invalid suite", "unsupported", "rejected", "truncated", "truncated body", "control", "untrusted", "identity", "cryptogram"} {
			t.Run(mode, func(t *testing.T) {
				p := newHandshakePeer(t, suite)
				parameters := p.parameters()
				invalidates := false

				switch mode {
				case "encoding":
					parameters.Encoding = iso7816.EncodingAuto
				case "missing suite":
					parameters.CipherSuite = 0
				case "invalid suite":
					parameters.CipherSuite = protocol.ECCP256
				case "unsupported":
					other := protocol.CipherSuite2
					if suite.algorithm == other {
						other = protocol.CipherSuite7
					}

					p.application = bytes.ReplaceAll(p.application, []byte{0x80, 1, byte(suite.algorithm)}, []byte{0x80, 1, byte(other)})
				case "rejected":
					p.handshake = func(iso7816.Response) iso7816.Response { return iso7816.Response{Status: 0x6a86} }
				case "truncated":
					p.handshake = func(iso7816.Response) iso7816.Response {
						return iso7816.Response{Data: []byte{0x7c, 0}, Status: 0x9000}
					}
					invalidates = true
				case "truncated body":
					p.handshake = func(iso7816.Response) iso7816.Response {
						data := make([]byte, 1+suite.nonceSize+16)
						return iso7816.Response{Data: bertlv.Append(nil, 0x7c, bertlv.Append(nil, 0x82, data)), Status: 0x9000}
					}
					invalidates = true
				case "control":
					p.handshake = func(r iso7816.Response) iso7816.Response {
						_, _, cert, err := parseEstablishmentResponse(suite, r.Data)
						if err != nil {
							t.Fatal(err)
						}

						value := append([]byte{0x10}, make([]byte, suite.nonceSize+16)...)
						value = append(value, cert...)
						r.Data = bertlv.Append(nil, 0x7c, bertlv.Append(nil, 0x82, value))

						return r
					}
					invalidates = true
				case "untrusted":
					parameters.Trust.IssuerID[0] ^= 1
					invalidates = true
				case "identity":
					p.handshake = func(r iso7816.Response) iso7816.Response {
						_, _, cert, err := parseEstablishmentResponse(suite, r.Data)
						if err != nil {
							t.Fatal(err)
						}

						subject := bytes.Index(cert, []byte{0x5f, 0x20, 16})
						if subject < 0 {
							t.Fatal("missing CVC subject fixture")
						}

						cert[subject+3] ^= 1

						return r
					}
					invalidates = true
				case "cryptogram":
					p.handshake = func(r iso7816.Response) iso7816.Response {
						nonce, cryptogram, cert, err := parseEstablishmentResponse(suite, r.Data)
						if err != nil {
							t.Fatal(err)
						}

						cryptogram[0] ^= 1

						value := append([]byte{0}, nonce...)
						value = append(value, cryptogram...)
						value = append(value, cert...)
						r.Data = bertlv.Append(nil, 0x7c, bertlv.Append(nil, 0x82, value))

						return r
					}
					invalidates = true
				}

				channel, err := Open(t.Context(), p, parameters)
				if channel != nil || err == nil {
					t.Fatalf("Open = %v, %v, want no channel", channel, err)
				}

				wantRequests := 2

				switch mode {
				case "encoding", "missing suite", "invalid suite":
					wantRequests = 0
				case "unsupported":
					wantRequests = 1
				}

				if len(p.requests) != wantRequests {
					t.Fatalf("Open sent %d commands, want %d", len(p.requests), wantRequests)
				}

				var invalidated *transport.DeviceInvalidatedError
				if errors.As(err, &invalidated) != invalidates || (p.closeCalls == 1) != invalidates {
					t.Fatalf("Open = %v, closes=%d, want invalidated=%t", err, p.closeCalls, invalidates)
				}
			})
		}
	})
}

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
			p.effect = func(context.Context, iso7816.Command) (iso7816.Response, error) {
				<-p.closed
				return iso7816.Response{}, io.ErrClosedPipe
			}
			active := make(chan error, 1)

			go func() { _, err := channel.Exchange(t.Context(), readCommand()); active <- err }()

			synctest.Wait()

			queued := make(chan error, 1)

			go func() { _, err := channel.Exchange(t.Context(), readCommand()); queued <- err }()

			synctest.Wait()

			if err := channel.Close(); err != nil {
				t.Fatal(err)
			}

			synctest.Wait()

			if !errors.Is(<-queued, io.ErrClosedPipe) || !errors.Is(<-active, io.ErrClosedPipe) {
				t.Fatal("callers not released")
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
