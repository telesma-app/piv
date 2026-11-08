package client

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
)

func TestGetCertificateDERMapsAllSlots(t *testing.T) {
	for _, tc := range []struct {
		key       protocol.KeyReference
		objectTag byte
	}{
		{key: 0x9a, objectTag: 0x05},
		{key: 0x9c, objectTag: 0x0a},
		{key: 0x9d, objectTag: 0x0b},
		{key: 0x9e, objectTag: 0x01},
		{key: 0x82, objectTag: 0x0d},
		{key: 0x83, objectTag: 0x0e},
		{key: 0x84, objectTag: 0x0f},
		{key: 0x85, objectTag: 0x10},
		{key: 0x86, objectTag: 0x11},
		{key: 0x87, objectTag: 0x12},
		{key: 0x88, objectTag: 0x13},
		{key: 0x89, objectTag: 0x14},
		{key: 0x8a, objectTag: 0x15},
		{key: 0x8b, objectTag: 0x16},
		{key: 0x8c, objectTag: 0x17},
		{key: 0x8d, objectTag: 0x18},
		{key: 0x8e, objectTag: 0x19},
		{key: 0x8f, objectTag: 0x1a},
		{key: 0x90, objectTag: 0x1b},
		{key: 0x91, objectTag: 0x1c},
		{key: 0x92, objectTag: 0x1d},
		{key: 0x93, objectTag: 0x1e},
		{key: 0x94, objectTag: 0x1f},
		{key: 0x95, objectTag: 0x20},
	} {
		t.Run(fmt.Sprintf("%02x", tc.key), func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, tc.objectTag, 0},
				response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0}},
			}))

			der, err := c.GetCertificateDER(t.Context(), tc.key)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(der, []byte{0x30, 0}) {
				t.Errorf("DER = %x, want 3000", der)
			}
		})
	}
}

func TestGetCertificateDERDecodesCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "PIV read test"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	var compressed bytes.Buffer

	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(der); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		value []byte
		info  byte
	}{
		{name: "DER", value: der},
		{name: "GZIP", value: compressed.Bytes(), info: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := bertlv.Append(nil, 0x70, tc.value)
			inner = append(inner, 0x71, 1, tc.info, 0xfe, 0)
			response := iso7816.Response{Status: 0x9000, Data: bertlv.Append(nil, 0x53, inner)}
			command := []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0}
			c := NewClient(newScript(t,
				exchangeStep{command: command, response: response},
				exchangeStep{command: command, response: response},
			))

			got, err := c.GetCertificateDER(t.Context(), protocol.PIVAuthentication)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(got, der) {
				t.Errorf("DER = %x, want %x", got, der)
			}

			certificate, err := c.GetCertificate(t.Context(), protocol.PIVAuthentication)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(certificate.Raw, der) || certificate.Subject.CommonName != template.Subject.CommonName {
				t.Errorf("certificate = %+v, want original certificate", certificate.Subject)
			}
		})
	}
}

func TestGetCertificateDERPreservesUnparseableBytes(t *testing.T) {
	command := []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0}
	response := iso7816.Response{Status: 0x9000, Data: []byte{0x53, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xfe, 0}}
	c := NewClient(newScript(t,
		exchangeStep{command: command, response: response},
		exchangeStep{command: command, response: response},
	))

	der, err := c.GetCertificateDER(t.Context(), protocol.PIVAuthentication)
	if err != nil || !bytes.Equal(der, []byte{0x30, 0}) {
		t.Fatalf("GetCertificateDER = %x, %v; want 3000", der, err)
	}

	if _, err := c.GetCertificate(t.Context(), protocol.PIVAuthentication); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Errorf("GetCertificate = %v, want ErrInvalidResponse", err)
	}
}

func TestGetCertificateDERPreservesErrors(t *testing.T) {
	cause := errors.New("connection lost")
	for _, tc := range []struct {
		name     string
		response iso7816.Response
		err      error
		want     error
		status   iso7816.StatusWord
	}{
		{name: "transport", err: cause, want: cause},
		{name: "absent", response: iso7816.Response{Status: 0x6a82}, status: 0x6a82},
		{name: "denied", response: iso7816.Response{Status: 0x6982}, status: 0x6982},
		{name: "outer template", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 1}}, want: protocol.ErrInvalidResponse},
		{name: "certificate object", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 3, 0x71, 1, 0}}, want: protocol.ErrInvalidResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 5, 0}, response: tc.response, err: tc.err,
			}))

			_, err := c.GetCertificateDER(t.Context(), protocol.PIVAuthentication)
			if tc.status != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.status {
					t.Fatalf("error = %v, want APDU %s", err, tc.status)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestGetKeyHistory(t *testing.T) {
	url := "http://example.test/0123456789abcdef"
	inner := []byte{0xc1, 1, 2, 0xc2, 1, 1, 0xf3, byte(len(url))}
	inner = append(inner, url...)
	inner = append(inner, 0xfe, 0)
	c := NewClient(newScript(t, exchangeStep{
		command:  []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0c, 0},
		response: iso7816.Response{Status: 0x9000, Data: bertlv.Append(nil, 0x53, inner)},
	}))

	history, err := c.GetKeyHistory(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	want := protocol.KeyHistory{KeysWithOnCardCerts: 2, KeysWithOffCardCerts: 1, OffCardCertURL: url}
	if history != want {
		t.Errorf("history = %+v, want %+v", history, want)
	}
}

func TestGetKeyHistoryPreservesErrors(t *testing.T) {
	cause := errors.New("connection lost")
	for _, tc := range []struct {
		name     string
		response iso7816.Response
		err      error
		want     error
		status   iso7816.StatusWord
	}{
		{name: "transport", err: cause, want: cause},
		{name: "absent", response: iso7816.Response{Status: 0x6a82}, status: 0x6a82},
		{name: "denied", response: iso7816.Response{Status: 0x6982}, status: 0x6982},
		{name: "outer template", response: iso7816.Response{Status: 0x9000, Data: []byte{0x7e, 0}}, want: protocol.ErrInvalidResponse},
		{name: "missing count", response: iso7816.Response{Status: 0x9000, Data: []byte{0x53, 3, 0xc1, 1, 0}}, want: protocol.ErrInvalidResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient(newScript(t, exchangeStep{
				command: []byte{0, 0xcb, 0x3f, 0xff, 5, 0x5c, 3, 0x5f, 0xc1, 0x0c, 0}, response: tc.response, err: tc.err,
			}))

			_, err := c.GetKeyHistory(t.Context())
			if tc.status != 0 {
				var apdu *iso7816.APDUError
				if !errors.As(err, &apdu) || apdu.StatusWord() != tc.status {
					t.Fatalf("error = %v, want APDU %s", err, tc.status)
				}
			} else if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}
