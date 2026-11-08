package card

import (
	"context"
	"errors"
	"io"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

type objectReadCase struct {
	name     string
	selector []byte
	template uint32
	contents func(byte) []byte
	read     func(context.Context, *Device) (byte, error)
}

func objectReadCases() []objectReadCase {
	return []objectReadCase{
		{
			name: "certificate data", selector: []byte{0x5f, 0xc1, 0x0d}, template: 0x53,
			contents: func(marker byte) []byte {
				return protocol.EncodeCertificateData(protocol.CertificateData{
					DER: []byte{0x30, 0}, MSCUID: []byte{marker},
				})
			},
			read: func(ctx context.Context, c *Device) (byte, error) {
				certificate, err := c.GetCertificateData(ctx, protocol.RetiredKey1)
				if err != nil {
					return 0, err
				}

				return certificate.MSCUID[0], nil
			},
		},
		{
			name: "CHUID", selector: []byte{0x5f, 0xc1, 0x02}, template: 0x53,
			contents: func(marker byte) []byte {
				data := append([]byte{0x30, 25}, make([]byte, 25)...)
				data = append(data, 0x34, 16, marker)
				data = append(data, make([]byte, 15)...)

				return append(data, []byte("\x35\x0820301231\xfe\x00")...)
			},
			read: func(ctx context.Context, c *Device) (byte, error) {
				chuid, err := c.GetCHUID(ctx)
				return chuid.GUID[0], err
			},
		},
		{
			name: "CCC", selector: []byte{0x5f, 0xc1, 0x07}, template: 0x53,
			contents: func(marker byte) []byte { return []byte{0xf5, 1, marker, 0xfe, 0} },
			read: func(ctx context.Context, c *Device) (byte, error) {
				ccc, err := c.GetCCC(ctx)
				return ccc.DataModel, err
			},
		},
		{
			name: "printed information", selector: []byte{0x5f, 0xc1, 0x09}, template: 0x53,
			contents: func(marker byte) []byte {
				return append([]byte{1, 1, marker}, []byte("\x02\x00\x04\x092030DEC31\x05\x00\x06\x0f123456789012345\xfe\x00")...)
			},
			read: func(ctx context.Context, c *Device) (byte, error) {
				info, err := c.GetPrintedInformation(ctx)
				if err != nil {
					return 0, err
				}

				return info.Name[0], nil
			},
		},
		{
			name: "security object", selector: []byte{0x5f, 0xc1, 0x06}, template: 0x53,
			contents: func(marker byte) []byte {
				return protocol.EncodeSecurityObject(protocol.SecurityObjectData{
					Mapping:    []protocol.DataGroupMapping{{DataGroup: 1, ContainerID: 0x3000}},
					SignedData: []byte{marker},
				})
			},
			read: func(ctx context.Context, c *Device) (byte, error) {
				object, err := c.GetSecurityObject(ctx)
				if err != nil {
					return 0, err
				}

				return object.SignedData[0], nil
			},
		},
		{
			name: "pairing code", selector: []byte{0x5f, 0xc1, 0x23}, template: 0x53,
			contents: func(marker byte) []byte {
				return []byte{0x99, 8, marker, '0', '0', '0', '0', '0', '0', '0', 0xfe, 0}
			},
			read: func(ctx context.Context, c *Device) (byte, error) {
				code, err := c.GetPairingCode(ctx)
				if err != nil {
					return 0, err
				}

				return code[0], nil
			},
		},
		{
			name: "secure messaging certificate signer", selector: []byte{0x5f, 0xc1, 0x22}, template: 0x53,
			contents: func(marker byte) []byte {
				return protocol.EncodeSecureMessagingCertificateSigner(protocol.SecureMessagingCertificateSigner{
					CertificateDER: []byte{marker}, IntermediateCVC: []byte{0x7f, 0x21, 1, marker},
				})
			},
			read: func(ctx context.Context, c *Device) (byte, error) {
				signer, err := c.GetSecureMessagingCertificateSigner(ctx)
				if err != nil {
					return 0, err
				}

				if signer.IntermediateCVC[3] != signer.CertificateDER[0] {
					return 0, errors.New("intermediate CVC was not retained")
				}

				return signer.CertificateDER[0], nil
			},
		},
		{
			name: "fingerprints", selector: []byte{0x5f, 0xc1, 0x03}, template: 0x53,
			contents: func(marker byte) []byte { return objectBiometricData(protocol.BiometricFingerprint, marker) },
			read: func(ctx context.Context, c *Device) (byte, error) {
				biometric, err := c.GetFingerprints(ctx)
				if err != nil {
					return 0, err
				}

				return biometric.Record[0], nil
			},
		},
		{
			name: "facial image", selector: []byte{0x5f, 0xc1, 0x08}, template: 0x53,
			contents: func(marker byte) []byte { return objectBiometricData(protocol.BiometricFace, marker) },
			read: func(ctx context.Context, c *Device) (byte, error) {
				biometric, err := c.GetFacialImage(ctx)
				if err != nil {
					return 0, err
				}

				return biometric.Record[0], nil
			},
		},
		{
			name: "iris images", selector: []byte{0x5f, 0xc1, 0x21}, template: 0x53,
			contents: func(marker byte) []byte { return objectBiometricData(protocol.BiometricIris, marker) },
			read: func(ctx context.Context, c *Device) (byte, error) {
				biometric, err := c.GetIrisImages(ctx)
				if err != nil {
					return 0, err
				}

				return biometric.Record[0], nil
			},
		},
		{
			name: "biometric information", selector: []byte{0x7f, 0x61}, template: 0x7f61,
			contents: func(marker byte) []byte {
				return protocol.EncodeBiometricInformation(protocol.BiometricInformation{
					Templates: []protocol.BiometricInformationTemplate{{
						Reference: protocol.PrimaryFingerOCC, Finger: protocol.BiometricRightIndex,
						FormatOwner: 0x0101, FormatType: 0x0005,
						MinutiaeMinimum: 1, MinutiaeMaximum: marker,
					}},
				})
			},
			read: func(ctx context.Context, c *Device) (byte, error) {
				information, err := c.GetBiometricInformation(ctx)
				if err != nil {
					return 0, err
				}

				return information.Templates[0].MinutiaeMaximum, nil
			},
		},
	}
}

func (object objectReadCase) command() []byte {
	command := []byte{0, 0xcb, 0x3f, 0xff, byte(len(object.selector) + 2), 0x5c, byte(len(object.selector))}
	command = append(command, object.selector...)

	return append(command, 0)
}

func objectBiometricData(kind protocol.BiometricType, marker byte) []byte {
	date := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)

	return protocol.EncodeBiometricData(protocol.BiometricData{
		Header: protocol.BiometricHeader{
			SecurityOptions: 0x0d, CreationDate: date, ValidFrom: date, ValidUntil: date,
			BiometricType: kind,
		},
		Record: []byte{marker}, Signature: []byte{0x30, 0},
	})
}

func TestTypedObjectReads(t *testing.T) {
	for _, test := range objectReadCases() {
		t.Run(test.name, func(t *testing.T) {
			command := test.command()
			d, _ := newDevice(t,
				exchangeStep{command: command, response: iso7816.Response{
					Status: 0x9000, Data: bertlv.Append(nil, test.template, test.contents('1')),
				}},
				exchangeStep{command: command, response: iso7816.Response{
					Status: 0x9000, Data: bertlv.Append(nil, test.template, test.contents('2')),
				}},
			)

			for _, want := range []byte{'1', '2'} {
				if got, err := test.read(t.Context(), d); err != nil || got != want {
					t.Fatalf("read = %02x, %v, want %02x", got, err, want)
				}
			}
		})
	}
}

func TestTypedObjectReadsPreserveErrors(t *testing.T) {
	cause := errors.New("card disconnected")

	for _, object := range objectReadCases() {
		t.Run(object.name, func(t *testing.T) {
			for _, test := range []struct {
				name     string
				response iso7816.Response
				err      error
				want     error
				status   iso7816.StatusWord
			}{
				{name: "absent", response: iso7816.Response{Status: 0x6a82}, status: 0x6a82},
				{name: "access denied", response: iso7816.Response{Status: 0x6982}, status: 0x6982},
				{name: "malformed contents", response: iso7816.Response{Status: 0x9000, Data: bertlv.Append(nil, object.template, []byte{0xfe, 0})}, want: protocol.ErrInvalidResponse},
				{name: "transport", err: cause, want: cause},
			} {
				t.Run(test.name, func(t *testing.T) {
					d, raw := newDevice(t, exchangeStep{
						command:  object.command(),
						response: test.response, err: test.err,
					})
					_, err := object.read(t.Context(), d)

					if test.status != 0 {
						var apdu *iso7816.APDUError
						if !errors.As(err, &apdu) || apdu.StatusWord() != test.status {
							t.Fatalf("read error = %v, want APDU %04x", err, uint16(test.status))
						}
					} else if !errors.Is(err, test.want) {
						t.Fatalf("read error = %v, want %v", err, test.want)
					}

					if raw.closeCalls != 0 {
						t.Errorf("read error closed the session: %d closes", raw.closeCalls)
					}
				})
			}
		})
	}
}

func TestTypedObjectReadsInvalidationClosesSession(t *testing.T) {
	cause := errors.New("card disconnected")
	closeError := errors.New("close failed")

	for _, object := range objectReadCases() {
		t.Run(object.name, func(t *testing.T) {
			d, raw := newDevice(t, exchangeStep{
				command: object.command(),
				err:     &transport.DeviceInvalidatedError{Err: cause},
			})
			raw.closeErr = closeError

			_, err := object.read(t.Context(), d)
			if !errors.Is(err, cause) || !errors.Is(err, closeError) {
				t.Fatalf("invalidation error = %v, want I/O and close errors", err)
			}

			var invalidated *transport.DeviceInvalidatedError
			if !errors.As(err, &invalidated) {
				t.Errorf("lost invalidation type: %v", err)
			}

			if _, err := object.read(t.Context(), d); !errors.Is(err, io.ErrClosedPipe) || raw.closeCalls != 1 {
				t.Errorf("after invalidation: error=%v, close calls=%d", err, raw.closeCalls)
			}
		})
	}
}

func TestTypedObjectReadsRespectSession(t *testing.T) {
	for _, object := range objectReadCases() {
		t.Run(object.name, func(t *testing.T) {
			t.Run("canceled while waiting", func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					d, raw := newDevice(t)
					if err := d.lock(t.Context()); err != nil {
						t.Fatal(err)
					}

					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()

					result := make(chan error, 1)
					done := make(chan struct{})

					go func() {
						defer close(done)

						_, err := object.read(ctx, d)
						result <- err
					}()

					defer func() {
						cancel()
						d.unlock()
						receive(t, done, "object read worker did not stop after cancellation and gate release")
					}()

					synctest.Wait()

					select {
					case err := <-result:
						t.Fatalf("object read completed while the workflow gate was held: %v", err)
					default:
					}

					cancel()

					if err := receive(t, result, "queued object read ignored cancellation"); !errors.Is(err, context.Canceled) || raw.calls != 0 || raw.closeCalls != 0 {
						t.Errorf("canceled read = %v, calls=%d, closes=%d", err, raw.calls, raw.closeCalls)
					}
				})
			})
			t.Run("closed", func(t *testing.T) {
				d, raw := newDevice(t)
				if err := d.Close(); err != nil {
					t.Fatal(err)
				}

				if _, err := object.read(t.Context(), d); !errors.Is(err, io.ErrClosedPipe) || raw.calls != 0 || raw.closeCalls != 1 {
					t.Errorf("closed read = %v, calls=%d, closes=%d", err, raw.calls, raw.closeCalls)
				}
			})
		})
	}
}
