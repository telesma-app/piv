package credential

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestVerifySignerRequiresContentSigningProfile(t *testing.T) {
	rootKey, leafKey := signerKey(t), signerKey(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signer profile root"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root := issueSignerCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	pivPolicy := signerPolicy(t, "2.16.840.1.101.3.2.1.3.39")
	otherPolicy := signerPolicy(t, "1.2.3.4")

	for _, tc := range []struct {
		name     string
		change   func(*x509.Certificate)
		wantPass bool
	}{
		{name: "content signer", change: func(*x509.Certificate) {}, wantPass: true},
		{name: "missing digital signature usage", change: func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageKeyEncipherment
		}},
		{name: "missing content signing EKU", change: func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = nil
		}},
		{name: "different custom EKU", change: func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}},
		{name: "missing PIV policy", change: func(c *x509.Certificate) {
			c.Policies = nil
		}},
		{name: "different policy", change: func(c *x509.Certificate) {
			c.Policies = []x509.OID{otherPolicy}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "profile content signer"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage:           x509.KeyUsageDigitalSignature,
				UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 16, 840, 1, 101, 3, 6, 7}}, Policies: []x509.OID{pivPolicy},
			}
			tc.change(leafTemplate)

			leaf := issueSignerCertificate(t, leafTemplate, root, &leafKey.PublicKey, rootKey)
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
				t.Fatalf("fixture has an invalid X.509 path: %v", err)
			}

			err := verifySigner(leaf, x509.VerifyOptions{Roots: roots, CurrentTime: now})
			if tc.wantPass {
				if err != nil {
					t.Errorf("verifySigner = %v, want accepted content signer", err)
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Errorf("verifySigner = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestVerifySignerRequiresTrustedCurrentCertificate(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	if err := verifySigner(fixture.cert, fixture.options); err != nil {
		t.Fatalf("valid signer: %v", err)
	}

	for _, tc := range []struct {
		name   string
		change func(*x509.VerifyOptions)
	}{
		{name: "explicit roots required", change: func(o *x509.VerifyOptions) { o.Roots = nil }},
		{name: "untrusted chain", change: func(o *x509.VerifyOptions) { o.Roots = x509.NewCertPool() }},
		{name: "expired certificate", change: func(o *x509.VerifyOptions) {
			o.CurrentTime = fixture.cert.NotAfter.Add(time.Second)
		}},
		{name: "certificate not valid yet", change: func(o *x509.VerifyOptions) {
			o.CurrentTime = fixture.cert.NotBefore.Add(-time.Second)
		}},
		{name: "caller key usage", change: func(o *x509.VerifyOptions) {
			o.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := fixture.options
			tc.change(&options)

			if err := verifySigner(fixture.cert, options); !errors.Is(err, ErrAuthentication) {
				t.Errorf("verifySigner = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestVerifySignerEnforcesChainEKU(t *testing.T) {
	rootKey, caKey, leafKey := signerKey(t), signerKey(t), signerKey(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pivPolicy := signerPolicy(t, "2.16.840.1.101.3.2.1.3.39")

	for _, location := range []string{"root", "intermediate"} {
		for _, tc := range []struct {
			name     string
			eku      []x509.ExtKeyUsage
			custom   []asn1.ObjectIdentifier
			wantPass bool
		}{
			{name: "unrestricted", wantPass: true},
			{name: "PIV", custom: []asn1.ObjectIdentifier{{2, 16, 840, 1, 101, 3, 6, 7}}, wantPass: true},
			{name: "Any", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, wantPass: true},
			{name: "serverAuth", eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		} {
			t.Run(location+"/"+tc.name, func(t *testing.T) {
				rootTemplate := &x509.Certificate{
					SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "chain EKU root"},
					NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
					IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
				}
				caTemplate := &x509.Certificate{
					SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "chain EKU intermediate"},
					NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
					IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
				}

				constrained := rootTemplate
				if location == "intermediate" {
					constrained = caTemplate
				}

				constrained.ExtKeyUsage, constrained.UnknownExtKeyUsage = tc.eku, tc.custom

				root := issueSignerCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
				ca := issueSignerCertificate(t, caTemplate, root, &caKey.PublicKey, rootKey)
				leafTemplate := &x509.Certificate{
					SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "chain EKU content signer"},
					NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
					KeyUsage:           x509.KeyUsageDigitalSignature,
					UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 16, 840, 1, 101, 3, 6, 7}}, Policies: []x509.OID{pivPolicy},
				}
				leaf := issueSignerCertificate(t, leafTemplate, ca, &leafKey.PublicKey, caKey)
				roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
				roots.AddCert(root)
				intermediates.AddCert(ca)

				err := verifySigner(leaf, x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now})
				if tc.wantPass {
					if err != nil {
						t.Errorf("verifySigner = %v, want accepted chain", err)
					}
				} else if !errors.Is(err, ErrAuthentication) {
					t.Errorf("verifySigner = %v, want ErrAuthentication", err)
				}
			})
		}
	}
}

func TestVerifySignerEnforcesCallerPolicies(t *testing.T) {
	rootKey, leafKey := signerKey(t), signerKey(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pivPolicy := signerPolicy(t, "2.16.840.1.101.3.2.1.3.39")
	callerPolicy := signerPolicy(t, "1.2.3.4")
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "caller policy root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root := issueSignerCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	for _, tc := range []struct {
		name      string
		policies  []x509.OID
		requested []x509.OID
		wantPass  bool
	}{
		{name: "PIV default", policies: []x509.OID{pivPolicy}, wantPass: true},
		{name: "caller policy present", policies: []x509.OID{pivPolicy, callerPolicy}, requested: []x509.OID{callerPolicy}, wantPass: true},
		{name: "caller policy absent", policies: []x509.OID{pivPolicy}, requested: []x509.OID{callerPolicy}},
		{name: "PIV policy absent", policies: []x509.OID{callerPolicy}, requested: []x509.OID{callerPolicy}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leafTemplate := &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "caller policy content signer"},
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
				KeyUsage:           x509.KeyUsageDigitalSignature,
				UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 16, 840, 1, 101, 3, 6, 7}}, Policies: tc.policies,
				// CreateCertificate does not marshal RequireExplicitPolicyZero.
				// policyConstraints: requireExplicitPolicy=0.
				ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 36}, Critical: true, Value: []byte{0x30, 3, 0x80, 1, 0}}},
			}

			leaf := issueSignerCertificate(t, leafTemplate, root, &leafKey.PublicKey, rootKey)
			if !leaf.RequireExplicitPolicyZero {
				t.Fatal("fixture does not require explicit certificate policies")
			}

			options := x509.VerifyOptions{Roots: roots, CurrentTime: now, CertificatePolicies: tc.requested}

			err := verifySigner(leaf, options)
			if tc.wantPass {
				if err != nil {
					t.Errorf("verifySigner = %v, want accepted policy", err)
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Errorf("verifySigner = %v, want ErrAuthentication", err)
			}
		})
	}
}

func TestVerifySignerRequiresPoliciesOnSameChain(t *testing.T) {
	rootKey, caKey, leafKey := signerKey(t), signerKey(t), signerKey(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	pivPolicy := signerPolicy(t, "2.16.840.1.101.3.2.1.3.39")
	callerPolicy := signerPolicy(t, "1.2.3.4")
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "alternate policy root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	root := issueSignerCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "alternate policy intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		Policies: []x509.OID{pivPolicy},
		// policyConstraints: requireExplicitPolicy=0.
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 36}, Critical: true, Value: []byte{0x30, 3, 0x80, 1, 0}}},
	}

	pivCA := issueSignerCertificate(t, caTemplate, root, &caKey.PublicKey, rootKey)
	if !pivCA.RequireExplicitPolicyZero {
		t.Fatal("fixture intermediate does not require explicit certificate policies")
	}

	caTemplate.SerialNumber, caTemplate.Policies = big.NewInt(3), []x509.OID{callerPolicy}
	callerCA := issueSignerCertificate(t, caTemplate, root, &caKey.PublicKey, rootKey)
	caTemplate.SerialNumber, caTemplate.Policies = big.NewInt(4), []x509.OID{pivPolicy, callerPolicy}
	commonCA := issueSignerCertificate(t, caTemplate, root, &caKey.PublicKey, rootKey)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "alternate policy content signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 16, 840, 1, 101, 3, 6, 7}}, Policies: []x509.OID{pivPolicy, callerPolicy},
	}
	leaf := issueSignerCertificate(t, leafTemplate, pivCA, &leafKey.PublicKey, caKey)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root)
	intermediates.AddCert(pivCA)
	intermediates.AddCert(callerCA)
	options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}

	// Each policy is independently satisfied, through a different signed CA
	// certificate with the same subject and public key.
	for _, tc := range []struct {
		policy x509.OID
		ca     *x509.Certificate
	}{{policy: pivPolicy, ca: pivCA}, {policy: callerPolicy, ca: callerCA}} {
		options.CertificatePolicies = []x509.OID{tc.policy}

		chains, err := leaf.Verify(options)
		if err != nil || len(chains) != 1 {
			t.Fatalf("fixture policy %s: chains=%d err=%v, want one valid path", tc.policy, len(chains), err)
		}

		if !bytes.Equal(chains[0][1].Raw, tc.ca.Raw) {
			t.Fatalf("fixture policy %s used the wrong intermediate", tc.policy)
		}
	}

	for _, tc := range []struct {
		name       string
		commonPath bool
	}{
		{name: "disjoint policy paths"},
		{name: "shared policy path", commonPath: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool := x509.NewCertPool()
			pool.AddCert(pivCA)
			pool.AddCert(callerCA)

			if tc.commonPath {
				pool.AddCert(commonCA)
			}

			options := x509.VerifyOptions{Roots: roots, Intermediates: pool, CurrentTime: now, CertificatePolicies: []x509.OID{callerPolicy}}

			err := verifySigner(leaf, options)
			if tc.commonPath {
				if err != nil {
					t.Errorf("verifySigner = %v, want accepted common policy path", err)
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Errorf("verifySigner = %v, want ErrAuthentication for disjoint policy paths", err)
			}
		})
	}
}

func signerKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func signerPolicy(t testing.TB, oid string) x509.OID {
	t.Helper()

	policy, err := x509.ParseOID(oid)
	if err != nil {
		t.Fatal(err)
	}

	return policy
}

func issueSignerCertificate(t testing.TB, template, parent *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, signer)
	if err != nil {
		t.Fatal(err)
	}

	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	return certificate
}
