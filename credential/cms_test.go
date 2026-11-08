package credential

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"
	"testing"
)

func TestCMSRejectsInvalidSignedDataProfile(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	content := []byte("signed PIV content")

	base, err := parseCMS(fixtureCMS(t, fixture, content, oidLDS, false, true, nil, nil))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifyCMS(base, fixture.cert, content, oidLDS, false); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name   string
		change func(*signedData)
	}{
		{name: "version 1", change: func(signed *signedData) { signed.Version = 1 }},
		{name: "CRLs present", change: func(signed *signedData) {
			signed.CRLs = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, IsCompound: true}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed := base
			tc.change(&signed)

			if _, err := parseCMS(encodeCMSFixture(t, signed)); !errors.Is(err, ErrAuthentication) {
				t.Errorf("parseCMS = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestSignedAttributesRequireDEROrder(t *testing.T) {
	// Independently encoded Attribute SEQUENCEs: content-type contains the
	// CHUID OID, and message-digest contains a 32-byte OCTET STRING. DER sorts
	// the complete encodings, so the shorter content-type attribute comes first.
	contentType := []byte{
		0x30, 0x17, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03,
		0x31, 0x0a, 0x06, 0x08, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x06, 0x01,
	}

	messageDigest := append([]byte{
		0x30, 0x2f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04,
		0x31, 0x22, 0x04, 0x20,
	}, make([]byte, 32)...)

	for _, tc := range []struct {
		name      string
		first     []byte
		second    []byte
		wantError bool
	}{
		{name: "ordered", first: contentType, second: messageDigest},
		{name: "reversed", first: messageDigest, second: contentType, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := append([]byte{0xa0, 0x4a}, tc.first...)
			wire = append(wire, tc.second...)

			var raw asn1.RawValue
			if rest, err := asn1.Unmarshal(wire, &raw); err != nil || len(rest) != 0 {
				t.Fatalf("decode signed attributes: rest %x, error %v", rest, err)
			}

			attrs, signed, err := signedAttributes(raw)
			if tc.wantError {
				if !errors.Is(err, ErrAuthentication) || attrs != nil || signed != nil {
					t.Errorf("signedAttributes = %v, %x, %v; want ErrAuthentication without attributes or signature input", attrs, signed, err)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if len(attrs) != 2 || !bytes.Equal(attrs[oidContentType.String()].FullBytes, contentType[13:]) || !bytes.Equal(attrs[oidMessageDigest.String()].FullBytes, messageDigest[13:]) {
				t.Errorf("signed attributes = %v, want content-type and message-digest values", attrs)
			}

			wantSigned := append([]byte{0x31, 0x4a}, contentType...)
			wantSigned = append(wantSigned, messageDigest...)

			if !bytes.Equal(signed, wantSigned) || wire[0] != 0xa0 {
				t.Errorf("signature input = %x, want %x without changing the wire tag", signed, wantSigned)
			}
		})
	}
}

func TestVerifyCMSRejectsSignedAttributeMisuse(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	content := []byte("external signed content")
	md := sha256.Sum256(content)

	base := []fixtureAttribute{fixtureAttr(t, oidContentType, oidCHUID), fixtureAttr(t, oidMessageDigest, md[:]), fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawSubject})}
	for _, tc := range []struct {
		name  string
		attrs []fixtureAttribute
	}{
		{"missing digest", []fixtureAttribute{base[0], base[2]}},
		{"duplicate digest", append(slices.Clone(base), base[1])},
		{"wrong content type", []fixtureAttribute{fixtureAttr(t, oidContentType, oidBiometric), base[1], base[2]}},
		{"wrong signer DN", []fixtureAttribute{base[0], base[1], fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawIssuer})}},
		{"wrong digest", []fixtureAttribute{base[0], fixtureAttr(t, oidMessageDigest, make([]byte, 32)), base[2]}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cms := fixtureCMS(t, fixture, content, oidCHUID, true, false, tc.attrs, nil)

			signed, err := parseCMS(cms)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := verifyCMS(signed, fixture.cert, content, oidCHUID, true); !errors.Is(err, ErrAuthentication) {
				t.Errorf("verifyCMS = %v", err)
			}
		})
	}
}

func TestCMSDigestSetMembership(t *testing.T) {
	fixture := newSigningFixture(t, nil)

	base, err := parseCMS(fixtureCMS(t, fixture, []byte("content"), oidLDS, false, true, nil, nil))
	if err != nil {
		t.Fatal(err)
	}

	for _, digests := range [][]pkix.AlgorithmIdentifier{
		nil,
		{{Algorithm: oidSHA384}},
		{{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}}},
	} {
		signed := base

		signed.Digests = digests
		if _, err := parseCMS(encodeCMSFixture(t, signed)); !errors.Is(err, ErrAuthentication) {
			t.Errorf("invalid digest set accepted: %v", err)
		}
	}

	base.Signers = nil
	if _, err := parseCMS(encodeCMSFixture(t, base)); !errors.Is(err, ErrAuthentication) {
		t.Errorf("empty signer set accepted: %v", err)
	}
}

func TestRSAAndPSSCMS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := newSigningFixture(t, key)

	content := []byte("signed PIV content")
	for _, salt := range []*int{nil, new(20), new(32)} {
		wire := fixtureCMS(t, fixture, content, oidCHUID, true, false, nil, salt)

		signed, err := parseCMS(wire)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := verifyCMS(signed, fixture.cert, content, oidCHUID, true); err != nil {
			t.Fatal(err)
		}
	}
}
