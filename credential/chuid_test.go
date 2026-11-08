package credential

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
	"time"

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
		{"expired certificate", func(_ *protocol.CHUID, o *x509.VerifyOptions) {
			o.CurrentTime = time.Date(2041, 1, 1, 0, 0, 0, 0, time.UTC)
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
