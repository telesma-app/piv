package sm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestTrustFromCertificate(t *testing.T) {
	_, signer := certificateKeys(t)
	_, rootKey := certificateKeys(t)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(root)
	options := x509.VerifyOptions{Roots: roots, CurrentTime: now}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test content signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidContentSigning},
		SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9},
	}

	rsaSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name         string
		change       func(*x509.Certificate, *x509.VerifyOptions)
		intermediate []byte
		wantPass     bool
	}{
		{name: "trusted content signer", change: func(*x509.Certificate, *x509.VerifyOptions) {}, wantPass: true},
		// Open authenticates the intermediate contents; this function borrows
		// the supplied bytes without parsing them.
		{name: "trusted RSA signer with intermediate", change: func(*x509.Certificate, *x509.VerifyOptions) {}, intermediate: []byte{0x7f, 0x21, 0}, wantPass: true},
		{name: "explicit roots required", change: func(_ *x509.Certificate, o *x509.VerifyOptions) { o.Roots = nil }},
		{name: "untrusted chain", change: func(_ *x509.Certificate, o *x509.VerifyOptions) { o.Roots = x509.NewCertPool() }},
		{name: "expired", change: func(_ *x509.Certificate, o *x509.VerifyOptions) { o.CurrentTime = now.Add(2 * time.Hour) }},
		{name: "missing digitalSignature", change: func(c *x509.Certificate, _ *x509.VerifyOptions) { c.KeyUsage = x509.KeyUsageKeyAgreement }},
		{name: "missing content signing EKU", change: func(c *x509.Certificate, _ *x509.VerifyOptions) { c.UnknownExtKeyUsage = nil }},
		{name: "short subjectKeyIdentifier", change: func(c *x509.Certificate, _ *x509.VerifyOptions) { c.SubjectKeyId = []byte{1} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			certTemplate, verifyOptions := *template, options
			test.change(&certTemplate, &verifyOptions)

			public := signer.Public()
			if test.intermediate != nil {
				public = &rsaSigner.PublicKey
			}

			der, err := x509.CreateCertificate(rand.Reader, &certTemplate, root, public, rootKey)
			if err != nil {
				t.Fatal(err)
			}

			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}

			trust, err := TrustFromCertificate(cert, verifyOptions, test.intermediate)
			if test.wantPass {
				if err != nil {
					t.Fatal(err)
				}

				if want := ([8]byte{1, 2, 3, 4, 5, 6, 7, 8}); trust.IssuerID != want {
					t.Errorf("issuer ID = %x, want %x", trust.IssuerID, want)
				}

				if trust.PublicKey != cert.PublicKey {
					t.Error("trust did not retain the certificate public key")
				}

				if test.intermediate == nil {
					if trust.IntermediateCVC != nil {
						t.Error("trust added an intermediate CVC")
					}
				} else if !bytes.Equal(trust.IntermediateCVC, test.intermediate) || &trust.IntermediateCVC[0] != &test.intermediate[0] {
					t.Error("trust did not borrow the intermediate CVC unchanged")
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Errorf("TrustFromCertificate = %v, want authentication error", err)
			}
		})
	}
}

func TestTrustFromCertificateEnforcesChainEKU(t *testing.T) {
	_, rootKey := certificateKeys(t)
	_, caKey := certificateKeys(t)
	_, signer := certificateKeys(t)
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		name     string
		caEKU    []x509.ExtKeyUsage
		caCustom []asn1.ObjectIdentifier
		caEmpty  bool
		rootEKU  []x509.ExtKeyUsage
		wantPass bool
	}{
		{name: "unrestricted CA", wantPass: true},
		{name: "PIV CA", caCustom: []asn1.ObjectIdentifier{oidContentSigning}, wantPass: true},
		{name: "Any CA", caEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, wantPass: true},
		{name: "serverAuth CA", caEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{name: "empty CA EKU", caEmpty: true},
		{name: "serverAuth root", rootEKU: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
	} {
		t.Run(test.name, func(t *testing.T) {
			rootTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
				ExtKeyUsage: test.rootEKU,
			}
			root := issueTestCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)

			caTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test intermediate"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
				ExtKeyUsage: test.caEKU, UnknownExtKeyUsage: test.caCustom,
			}
			if test.caEmpty {
				caTemplate.ExtraExtensions = []pkix.Extension{{Id: oidExtendedUsage, Value: []byte{0x30, 0}}}
			}

			ca := issueTestCertificate(t, caTemplate, root, &caKey.PublicKey, rootKey)
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "test content signer"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidContentSigning},
				SubjectKeyId: []byte{1, 2, 3, 4, 5, 6, 7, 8},
			}
			leaf := issueTestCertificate(t, leafTemplate, ca, &signer.PublicKey, caKey)
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			roots.AddCert(root)
			intermediates.AddCert(ca)

			_, err := TrustFromCertificate(leaf, x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now}, nil)
			if test.wantPass {
				if err != nil {
					t.Errorf("TrustFromCertificate = %v, want accepted chain", err)
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Errorf("TrustFromCertificate = %v, want authentication error", err)
			}
		})
	}
}

func issueTestCertificate(t testing.TB, template, parent *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}
