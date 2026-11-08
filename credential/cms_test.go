package credential

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"slices"
	"testing"
)

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
