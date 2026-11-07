package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

type inspectionResponse struct {
	response iso7816.Response
	err      error
}

// An empty card returns 6A82 for objects not explicitly installed by the test.
type inspectionTransport struct {
	t          testing.TB
	objects    map[protocol.Object]inspectionResponse
	requests   []protocol.Object
	closeCalls int
}

func (s *inspectionTransport) Exchange(ctx context.Context, command iso7816.Command) (iso7816.Response, error) {
	s.t.Helper()

	if command.INS == byte(protocol.Verify) && command.P2 == byte(protocol.ApplicationPIN) && len(command.Data) == 0 {
		return iso7816.Response{Status: 0x63c3}, nil
	}

	if command.INS != byte(protocol.GetData) || command.P1 != 0x3f || command.P2 != 0xff ||
		len(command.Data) < 3 || command.Data[0] != 0x5c || int(command.Data[1])+2 != len(command.Data) {
		s.t.Errorf("unexpected command: %+v", command)
		return iso7816.Response{}, io.ErrUnexpectedEOF
	}

	var object protocol.Object
	for _, b := range command.Data[2:] {
		object = object<<8 | protocol.Object(b)
	}

	s.requests = append(s.requests, object)
	if result, ok := s.objects[object]; ok {
		return result.response, result.err
	}

	return iso7816.Response{Status: 0x6a82}, nil
}

func (s *inspectionTransport) Close() error {
	s.closeCalls++
	return nil
}

func encodedObject(tag byte, value []byte) iso7816.Response {
	data := append([]byte{tag, 0x82, byte(len(value) >> 8), byte(len(value))}, value...)
	return iso7816.Response{Status: 0x9000, Data: data}
}

func encodedCertificate(der []byte) iso7816.Response {
	value := append([]byte{0x70, 0x82, byte(len(der) >> 8), byte(len(der))}, der...)
	return encodedObject(0x53, append(value, 0x71, 1, 0, 0xfe, 0))
}

func inspectionCertificate(t testing.TB) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "private cardholder name"},
		NotBefore:    time.Unix(1, 0),
		NotAfter:     time.Unix(2, 0),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func TestInspectReportsReaderAndOffCardCertificates(t *testing.T) {
	url := "http://certs.example/" + strings.Repeat("a", 64)
	history := []byte{0xc1, 1, 0, 0xc2, 1, 3, 0xf3, byte(len(url))}
	history = append(history, url...)
	history = append(history, 0xfe, 0)
	der := inspectionCertificate(t)
	raw := &inspectionTransport{t: t, objects: map[protocol.Object]inspectionResponse{
		protocol.KeyHistoryObject:            {response: encodedObject(0x53, history)},
		protocol.DigitalSignatureCertificate: {response: encodedCertificate(der)},
	}}

	device := card.NewWithApplicationProperties(raw, protocol.ApplicationPropertyTemplate{
		AID: []byte{1, 2, 3}, ApplicationLabel: "test PIV", Algorithms: []protocol.Algorithm{protocol.RSA2048, 0xee},
	})
	defer func() { _ = device.Close() }()

	var out bytes.Buffer

	if err := inspectCard(t.Context(), &out, "reader one", device); err != nil {
		t.Fatal(err)
	}

	text := out.String()
	for _, want := range []string{
		`reader "reader one": application "test PIV", AID 010203`,
		`reader "reader one": retired keys: 0 with on-card certificates, 3 with off-card certificates`,
		fmt.Sprintf("reader %q: off-card certificate URL: %q", "reader one", url),
		fmt.Sprintf("reader %q: certificate 9c: ECDSA, %d DER bytes", "reader one", len(der)),
		`reader "reader one": certificate 92: absent`,
		`reader "reader one": certificate 93: off-card`,
		`reader "reader one": certificate 94: off-card`,
		`reader "reader one": certificate 95: off-card`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("inspection output missing %q:\n%s", want, text)
		}
	}

	if got := strings.Count(text, ": certificate "); got != 24 {
		t.Errorf("certificate result count = %d, want 24", got)
	}

	if strings.Contains(text, "private cardholder name") {
		t.Error("inspection output contains the cardholder name")
	}

	if len(raw.requests) != 28 {
		t.Errorf("GET DATA count = %d, want 28", len(raw.requests))
	}
}

func TestInspectKeepsCertificatesAfterMetadataAndParsingErrors(t *testing.T) {
	der := inspectionCertificate(t)
	raw := &inspectionTransport{t: t, objects: map[protocol.Object]inspectionResponse{
		protocol.DiscoveryObject:              {response: iso7816.Response{Status: 0x9000, Data: []byte{0x7e, 1}}},
		protocol.KeyHistoryObject:             {response: iso7816.Response{Status: 0x6982}},
		protocol.PIVAuthenticationCertificate: {response: encodedCertificate([]byte{0x30, 0})},
		protocol.DigitalSignatureCertificate:  {response: encodedCertificate(der)},
	}}

	device := card.New(raw)
	defer func() { _ = device.Close() }()

	var out bytes.Buffer

	err := inspectCard(t.Context(), &out, "reader two", device)

	var apdu *iso7816.APDUError
	if !errors.Is(err, protocol.ErrInvalidResponse) || !errors.As(err, &apdu) || apdu.StatusWord() != 0x6982 {
		t.Fatalf("inspection error = %v, want parsing and access errors", err)
	}

	for _, want := range []string{
		`reader "reader two": certificate 9a: 2 DER bytes,`,
		`reader "reader two": certificate 9c: ECDSA,`,
		`reader "reader two": certificate 95: absent`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("inspection output missing %q:\n%s", want, out.String())
		}
	}

	if len(raw.requests) != 28 || raw.closeCalls != 0 {
		t.Errorf("after partial errors: reads=%d closes=%d, want 28 and 0", len(raw.requests), raw.closeCalls)
	}
}

func TestInspectStopsAfterTerminalMetadataFailure(t *testing.T) {
	cause := &transport.DeviceInvalidatedError{Err: protocol.ErrInvalidResponse}
	raw := &inspectionTransport{t: t, objects: map[protocol.Object]inspectionResponse{
		protocol.KeyHistoryObject: {err: cause},
	}}

	device := card.New(raw)
	defer func() { _ = device.Close() }()

	var out bytes.Buffer

	err := inspectCard(t.Context(), &out, "removed card", device)
	if !errors.Is(err, cause) {
		t.Fatalf("inspection error = %v, want original invalidation", err)
	}

	if len(raw.requests) != 4 || raw.closeCalls != 1 {
		t.Errorf("after invalidation: reads=%d closes=%d, want 4 and 1", len(raw.requests), raw.closeCalls)
	}

	if strings.Contains(out.String(), ": certificate ") {
		t.Error("inspection continued with certificate reads after invalidation")
	}
}

func TestInspectDoesNotHideInvalidationAsMissingCertificate(t *testing.T) {
	cause := &transport.DeviceInvalidatedError{Err: &iso7816.APDUError{SW1: 0x6a, SW2: 0x82}}
	raw := &inspectionTransport{t: t, objects: map[protocol.Object]inspectionResponse{
		protocol.DigitalSignatureCertificate: {err: cause},
	}}

	device := card.New(raw)
	defer func() { _ = device.Close() }()

	var out bytes.Buffer

	err := inspectCard(t.Context(), &out, "removed card", device)
	if !errors.Is(err, cause) {
		t.Fatalf("inspection error = %v, want original invalidation", err)
	}

	if len(raw.requests) != 6 || raw.closeCalls != 1 {
		t.Errorf("after invalidation: reads=%d closes=%d, want 6 and 1", len(raw.requests), raw.closeCalls)
	}

	if strings.Contains(out.String(), "certificate 9c: absent") {
		t.Error("inspection reported invalidation as an absent certificate")
	}
}
