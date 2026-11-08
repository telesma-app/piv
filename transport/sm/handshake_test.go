package sm

import (
	"bytes"
	"errors"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func TestOpenEstablishesSession(t *testing.T) {
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

			if !channel.PIVSecureMessaging() || channel.session.counter != [16]byte{15: 1} {
				t.Fatal("session not active or initial counter is incorrect")
			}

			if channel.session.keys.cfrm != [32]byte{} {
				t.Fatal("key confirmation key retained in session")
			}

			if len(p.requests) != 2 || p.requests[0].INS != 0xa4 || p.requests[1].INS != 0x87 {
				t.Fatalf("Open requests = %+v, want SELECT and GENERAL AUTHENTICATE", p.requests)
			}

			if channel.session.encoding != encoding || channel.session.keys.keySize != suite.keySize {
				t.Fatalf("session encoding/key size = %v/%d, want %v/%d", channel.session.encoding, channel.session.keys.keySize, encoding, suite.keySize)
			}
		}
	})
}

func TestFailedOpenOwnership(t *testing.T) {
	testCipherSuites(t, func(t *testing.T, suite cipherSuite) {
		for _, tc := range []struct {
			name        string
			want        error
			status      iso7816.StatusWord
			exchanges   int
			invalidates bool
		}{
			{name: "encoding"},
			{name: "missing suite"},
			{name: "invalid suite"},
			{name: "unsupported", exchanges: 1},
			{name: "rejected", status: 0x6a86, exchanges: 2},
			{name: "truncated", want: ErrInvalidResponse, exchanges: 2, invalidates: true},
			{name: "truncated body", want: ErrInvalidResponse, exchanges: 2, invalidates: true},
			{name: "control", want: ErrAuthentication, exchanges: 2, invalidates: true},
			{name: "untrusted", want: ErrAuthentication, exchanges: 2, invalidates: true},
			{name: "identity", want: ErrAuthentication, exchanges: 2, invalidates: true},
			{name: "cryptogram", want: ErrAuthentication, exchanges: 2, invalidates: true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				p := newHandshakePeer(t, suite)
				parameters := p.parameters()

				switch tc.name {
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
				case "truncated body":
					p.handshake = func(iso7816.Response) iso7816.Response {
						data := make([]byte, 1+suite.nonceSize+16)
						return iso7816.Response{Data: bertlv.Append(nil, 0x7c, bertlv.Append(nil, 0x82, data)), Status: 0x9000}
					}
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
				case "untrusted":
					parameters.Trust.IssuerID[0] ^= 1
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
				}

				channel, err := Open(t.Context(), p, parameters)
				if channel != nil || err == nil {
					t.Fatalf("Open = %v, %v, want no channel", channel, err)
				}

				if tc.want != nil && !errors.Is(err, tc.want) {
					t.Errorf("Open error = %v, want %v", err, tc.want)
				}

				if tc.status != 0 {
					var apduError *iso7816.APDUError
					if !errors.As(err, &apduError) || apduError.StatusWord() != tc.status {
						t.Errorf("Open error = %v, want APDU status %s", err, tc.status)
					}
				}

				if len(p.requests) != tc.exchanges {
					t.Errorf("Open sent %d commands, want %d", len(p.requests), tc.exchanges)
				}

				wantCloses := 0
				if tc.invalidates {
					wantCloses = 1
				}

				var invalidated *transport.DeviceInvalidatedError
				if errors.As(err, &invalidated) != tc.invalidates || p.closeCalls != wantCloses {
					t.Fatalf("Open = %v, closes=%d; want invalidated=%t, closes=%d", err, p.closeCalls, tc.invalidates, wantCloses)
				}
			})
		}
	})
}
