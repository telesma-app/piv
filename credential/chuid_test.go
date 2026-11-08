package credential

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/piv/protocol"
)

func TestVerifyCHUID(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	chuid := fixtureCHUID(t, fixture)

	got, err := VerifyCHUID(chuid, fixture.options)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Raw, fixture.cert.Raw) {
		t.Error("returned a different signer")
	}

	for _, tc := range []struct {
		name string
		edit func(*protocol.CHUID, *x509.VerifyOptions)
	}{
		{"tampered content", func(c *protocol.CHUID, _ *x509.VerifyOptions) { c.Raw[3] ^= 1 }},
		{"tampered signature", func(c *protocol.CHUID, _ *x509.VerifyOptions) { c.IssuerSignature[len(c.IssuerSignature)-1] ^= 1 }},
		{"untrusted root", func(_ *protocol.CHUID, o *x509.VerifyOptions) { o.Roots = x509.NewCertPool() }},
		{"no roots", func(_ *protocol.CHUID, o *x509.VerifyOptions) { o.Roots = nil }},
		{"expired card", func(_ *protocol.CHUID, o *x509.VerifyOptions) {
			o.CurrentTime = time.Date(2032, 1, 1, 0, 0, 0, 0, time.UTC)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := fixtureCHUID(t, fixture)
			o := fixture.options
			tc.edit(&c, &o)

			if _, err := VerifyCHUID(c, o); !errors.Is(err, ErrAuthentication) {
				t.Errorf("VerifyCHUID = %v, want authentication error", err)
			}
		})
	}

	options := fixture.options

	options.CurrentTime = time.Date(2031, 12, 31, 23, 59, 59, 999999999, time.UTC)
	if _, err := VerifyCHUID(chuid, options); err != nil {
		t.Errorf("last moment on expiry date rejected: %v", err)
	}
}

func TestVerifyCHUIDRejectsExpiredSignerCertificate(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	chuid := fixtureCHUIDWithExpiration(t, fixture, "20491231")
	options := fixture.options

	options.CurrentTime = time.Date(2041, 1, 1, 0, 0, 0, 0, time.UTC)
	if !options.CurrentTime.Before(chuid.ExpirationDate) {
		t.Fatal("fixture CHUID has expired")
	}

	certificate, err := VerifyCHUID(chuid, options)

	var invalid x509.CertificateInvalidError
	if !errors.Is(err, ErrAuthentication) || !errors.As(err, &invalid) || invalid.Reason != x509.Expired {
		t.Errorf("VerifyCHUID = %v, want an expired certificate error", err)
	}

	if certificate != nil {
		t.Error("VerifyCHUID returned an expired signer certificate")
	}
}

func TestVerifyCHUIDRequiresSingleSignerAndDigest(t *testing.T) {
	fixture := newSigningFixture(t, nil)

	chuid := fixtureCHUID(t, fixture)
	if _, err := VerifyCHUID(chuid, fixture.options); err != nil {
		t.Fatalf("valid CHUID: %v", err)
	}

	for _, tc := range []struct {
		name   string
		modify func(*signedData)
	}{
		{name: "multiple signers", modify: func(signed *signedData) {
			signed.Signers = append(signed.Signers, signed.Signers[0])
		}},
		{name: "multiple digests", modify: func(signed *signedData) {
			signed.Digests = append(signed.Digests, pkix.AlgorithmIdentifier{Algorithm: oidSHA384, Parameters: asn1.NullRawValue})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := parseCMS(chuid.IssuerSignature)
			if err != nil {
				t.Fatal(err)
			}

			tc.modify(&signed)
			signature := encodeCMSFixture(t, signed)

			var wire []byte

			for data := chuid.Raw; len(data) != 0; {
				tag, _, rest, err := bertlv.Parse(data)
				if err != nil {
					t.Fatal(err)
				}

				if tag == 0x3e {
					wire = bertlv.Append(wire, tag, signature)
				} else {
					wire = append(wire, data[:len(data)-len(rest)]...)
				}

				data = rest
			}

			invalid, err := protocol.ParseCHUID(wire)
			if err != nil {
				t.Fatal(err)
			}

			certificate, err := VerifyCHUID(invalid, fixture.options)
			if !errors.Is(err, ErrAuthentication) {
				t.Errorf("VerifyCHUID = %v, want ErrAuthentication", err)
			}

			if certificate != nil {
				t.Error("VerifyCHUID returned a signer for an invalid CMS profile")
			}
		})
	}
}
