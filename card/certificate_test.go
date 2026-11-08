package card

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"testing/synctest"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func readCertificateDER(t testing.TB) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "inventory certificate"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func readTLV(tag byte, data []byte) []byte {
	if len(data) < 128 {
		return append([]byte{tag, byte(len(data))}, data...)
	}

	return append([]byte{tag, 0x82, byte(len(data) >> 8), byte(len(data))}, data...)
}

func certificateResponse(data []byte, info byte) iso7816.Response {
	inner := append(readTLV(0x70, data), 0x71, 1, info, 0xfe, 0)
	return iso7816.Response{Status: 0x9000, Data: readTLV(0x53, inner)}
}

func compressedCertificate(t testing.TB, data []byte) []byte {
	t.Helper()

	var buffer bytes.Buffer

	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return buffer.Bytes()
}

func absentCertificateSteps() []exchangeStep {
	// Independent expected GET DATA selectors: four primary objects, then the
	// twenty retired certificate objects. Do not derive them from CertificateObject.
	objects := [24]byte{
		0x05, 0x0a, 0x0b, 0x01,
		0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
		0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}

	steps := make([]exchangeStep, len(objects))
	for i, object := range objects {
		steps[i] = exchangeStep{
			command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, object, 0},
			response: iso7816.Response{Status: 0x6a82},
		}
	}

	return steps
}

func TestCertificatesReadsEverySlotAndPreservesFailures(t *testing.T) {
	der := readCertificateDER(t)
	invalidDER := []byte{0x30, 0}
	steps := absentCertificateSteps()
	steps[0].response = certificateResponse(der, 0)
	steps[2].response = iso7816.Response{Status: 0x6982}
	steps[3].response = iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1}}
	steps[4].response = certificateResponse(invalidDER, 0)
	steps[5].response = certificateResponse(compressedCertificate(t, der), 1)
	d, _ := newDevice(t, steps...)
	wantKeys := [24]protocol.KeyReference{
		0x9a, 0x9c, 0x9d, 0x9e,
		0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b,
		0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
	}

	var count int
	for entry, err := range d.Certificates(t.Context()) {
		if count >= len(wantKeys) {
			t.Fatal("enumeration yielded more than 24 slots")
		}

		if entry.Key != wantKeys[count] {
			t.Errorf("entry %d key = %02x, want %02x", count, entry.Key, wantKeys[count])
		}

		switch count {
		case 0, 5:
			if err != nil {
				t.Fatal(err)
			}

			if entry.Certificate == nil || !bytes.Equal(entry.Certificate.Raw, der) || !bytes.Equal(entry.DER, der) {
				t.Errorf("entry %d did not preserve the parsed certificate and DER", count)
			}
		case 3, 4:
			if !errors.Is(err, protocol.ErrInvalidResponse) || entry.Certificate != nil {
				t.Errorf("entry %d = %+v, %v; want parsing failure", count, entry, err)
			}

			if count == 3 && entry.DER != nil {
				t.Error("malformed object returned DER")
			}

			if count == 4 && !bytes.Equal(entry.DER, invalidDER) {
				t.Error("X.509 parsing failure discarded decoded DER")
			}
		default:
			wantStatus := iso7816.StatusWord(0x6a82)
			if count == 2 {
				wantStatus = 0x6982
			}

			var apdu *iso7816.APDUError
			if !errors.As(err, &apdu) || apdu.StatusWord() != wantStatus {
				t.Errorf("entry %d error = %v, want APDU %s", count, err, wantStatus)
			}

			if entry.DER != nil || entry.Certificate != nil {
				t.Errorf("entry %d returned certificate data after APDU rejection", count)
			}
		}

		count++
	}

	if count != len(wantKeys) {
		t.Errorf("slot count = %d, want %d", count, len(wantKeys))
	}
}

func TestGetCertificateDERDoesNotParseX509(t *testing.T) {
	opaque := []byte{0xff, 1, 2, 3}

	for _, compressed := range []bool{false, true} {
		name := "uncompressed"
		data, info := opaque, byte(0)

		if compressed {
			name = "GZIP"
			data, info = compressedCertificate(t, opaque), 1
		}

		t.Run(name, func(t *testing.T) {
			d, _ := newDevice(t, exchangeStep{
				command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x20, 0},
				response: certificateResponse(data, info),
			})

			der, err := d.GetCertificateDER(t.Context(), protocol.RetiredKey20)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(der, opaque) {
				t.Errorf("GetCertificateDER = %x, want %x", der, opaque)
			}
		})
	}
}

func TestCertificatesIsLazyAndStopsAtBreak(t *testing.T) {
	d, raw := newDevice(t, exchangeStep{
		command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0},
		response: certificateResponse(readCertificateDER(t), 0),
	})

	sequence := d.Certificates(t.Context())
	if raw.calls != 0 {
		t.Fatal("creating the iterator performed I/O")
	}

	for entry, err := range sequence {
		if err != nil {
			t.Fatal(err)
		}

		if entry.Key != protocol.PIVAuthentication {
			t.Errorf("key = %02x, want 9A", entry.Key)
		}

		break
	}

	if raw.calls != 1 {
		t.Errorf("exchange count after break = %d, want 1", raw.calls)
	}
}

func TestCertificatesPreservesRetiredMSCUID(t *testing.T) {
	steps := absentCertificateSteps()
	contents := []byte{0x70, 2, 0x30, 0, 0x71, 1, 0, 0x72, 3, 'o', 'l', 'd', 0xfe, 0}
	steps[4].response = iso7816.Response{Status: 0x9000, Data: readTLV(0x53, contents)}
	d, _ := newDevice(t, steps...)

	var count int
	for entry, err := range d.Certificates(t.Context()) {
		count++

		if entry.Key == protocol.RetiredKey1 {
			if !errors.Is(err, protocol.ErrInvalidResponse) || entry.Certificate != nil ||
				!bytes.Equal(entry.DER, []byte{0x30, 0}) || string(entry.MSCUID) != "old" {
				t.Errorf("retired certificate = %+v, %v; want preserved DER/MSCUID despite invalid X.509", entry, err)
			}
		}
	}

	if count != 24 {
		t.Errorf("certificate count = %d, want 24", count)
	}
}

func TestCertificatesReleasesGateBeforeYield(t *testing.T) {
	der := readCertificateDER(t)
	synctest.Test(t, func(t *testing.T) {
		d, _ := newDevice(t,
			exchangeStep{
				command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0}, response: certificateResponse(der, 0),
			},
			exchangeStep{command: []byte{0, 0x20, 0, 0x80}, response: iso7816.Response{Status: 0x63c3}},
		)

		for _, err := range d.Certificates(t.Context()) {
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			status, err := d.ReferenceStatus(ctx, protocol.ApplicationPIN)

			cancel()

			if err != nil || status.Retries != 3 {
				t.Fatalf("ReferenceStatus from yield = %+v, %v; want three retries", status, err)
			}

			break
		}
	})
}

func TestCertificatesStopsOnTerminalReadError(t *testing.T) {
	cause := errors.New("transmit failed")
	for _, tc := range []struct {
		name  string
		err   error
		close bool
	}{
		{name: "invalidation wrapping parse error", err: &transport.DeviceInvalidatedError{Err: protocol.ErrInvalidResponse}, close: true},
		{name: "I/O", err: &transport.IOError{Operation: transport.IOTransmit, Err: cause}},
		{name: "unknown transport failure", err: cause},
		{name: "canceled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "closed", err: io.ErrClosedPipe},
		{name: "I/O wrapping parse error", err: &transport.IOError{Operation: transport.IOTransmit, Err: protocol.ErrInvalidResponse}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, raw := newDevice(t, exchangeStep{
				command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0}, err: tc.err,
			})

			var count int
			for entry, err := range d.Certificates(t.Context()) {
				count++

				if entry.Key != protocol.PIVAuthentication || entry.DER != nil || entry.Certificate != nil {
					t.Errorf("failed entry = %+v, want key 9A without certificate", entry)
				}

				if !errors.Is(err, tc.err) {
					t.Errorf("terminal error = %v, want cause %v", err, tc.err)
				}
			}

			if count != 1 {
				t.Errorf("entry count = %d, want one terminal entry", count)
			}

			wantCloses := 0
			if tc.close {
				wantCloses = 1
			}

			if raw.closeCalls != wantCloses {
				t.Errorf("close count = %d, want %d", raw.closeCalls, wantCloses)
			}
		})
	}
}

func TestCertificatesCanceledBeforeReadDoesNotTransmit(t *testing.T) {
	d, raw := newDevice(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	var count int
	for entry, err := range d.Certificates(ctx) {
		count++

		if entry.Key != protocol.PIVAuthentication || !errors.Is(err, context.Canceled) {
			t.Errorf("entry = %+v, %v; want key 9A and cancellation", entry, err)
		}
	}

	if count != 1 || raw.calls != 0 || raw.closeCalls != 0 {
		t.Errorf("canceled enumeration: entries=%d exchanges=%d closes=%d", count, raw.calls, raw.closeCalls)
	}
}

func TestCertificatesCloseInYieldStopsBeforeNextIO(t *testing.T) {
	d, _ := newDevice(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0}, response: certificateResponse(readCertificateDER(t), 0),
	})

	var count int
	for entry, err := range d.Certificates(t.Context()) {
		count++
		switch count {
		case 1:
			if entry.Key != protocol.PIVAuthentication || err != nil {
				t.Fatalf("first entry = %+v, %v", entry, err)
			}

			if err := d.Close(); err != nil {
				t.Fatal(err)
			}
		case 2:
			if entry.Key != protocol.DigitalSignature || !errors.Is(err, io.ErrClosedPipe) {
				t.Errorf("entry after Close = %+v, %v; want key 9C and ErrClosedPipe", entry, err)
			}
		default:
			t.Fatalf("unexpected entry after terminal closure: %+v, %v", entry, err)
		}
	}

	if count != 2 {
		t.Errorf("entry count = %d, want completed and terminal entries", count)
	}
}

func TestCertificatesPreservesCompletedReadAfterCancellation(t *testing.T) {
	der := readCertificateDER(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	d, raw := newDevice(t, exchangeStep{
		command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0}, response: certificateResponse(der, 0), after: cancel,
	})

	var count int
	for entry, err := range d.Certificates(ctx) {
		count++
		switch count {
		case 1:
			if entry.Key != protocol.PIVAuthentication || err != nil || entry.Certificate == nil || !bytes.Equal(entry.DER, der) {
				t.Errorf("completed entry = %+v, %v; want original certificate", entry, err)
			}
		case 2:
			if entry.Key != protocol.DigitalSignature || !errors.Is(err, context.Canceled) {
				t.Errorf("terminal entry = %+v, %v; want key 9C and cancellation", entry, err)
			}
		default:
			t.Fatalf("unexpected entry after cancellation: %+v, %v", entry, err)
		}
	}

	if count != 2 || raw.closeCalls != 0 {
		t.Errorf("completed read followed by cancellation: entries=%d closes=%d", count, raw.closeCalls)
	}
}
