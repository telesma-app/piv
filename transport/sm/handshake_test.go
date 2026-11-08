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
