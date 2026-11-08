package credential

import (
	"crypto/sha256"
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
