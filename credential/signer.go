package credential

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
)

var (
	oidContentSigning = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 7}
	oidContentPolicy  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 39}
)

func verifySigner(certificate *x509.Certificate, options x509.VerifyOptions) error {
	if options.Roots == nil {
		return fmt.Errorf("%w: explicit certificate roots are required", ErrAuthentication)
	}

	if certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.ContainsFunc(certificate.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool { return oid.Equal(oidContentSigning) }) || !slices.ContainsFunc(certificate.PolicyIdentifiers, func(oid asn1.ObjectIdentifier) bool { return oid.Equal(oidContentPolicy) }) {
		return fmt.Errorf("%w: certificate is not a PIV content signer", ErrAuthentication)
	}

	if len(options.KeyUsages) == 0 {
		// crypto/x509 has no ExtKeyUsage value for the PIV OID. Its custom EKU
		// is checked below throughout the verified chain instead.
		options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	requestedPolicies := options.CertificatePolicies

	policy, err := x509.OIDFromInts([]uint64{2, 16, 840, 1, 101, 3, 2, 1, 3, 39})
	if err != nil {
		panic(err)
	}

	options.CertificatePolicies = []x509.OID{policy}

	chains, err := certificate.Verify(options)
	if err != nil {
		return fmt.Errorf("%w: content-signing certificate: %w", ErrAuthentication, err)
	}

	if len(requestedPolicies) != 0 {
		// PIV content signing and the caller's policy constraints must hold on
		// the same path, rather than either independently acceptable path.
		options.CertificatePolicies = requestedPolicies

		callerChains, err := certificate.Verify(options)
		if err != nil {
			return fmt.Errorf("%w: caller certificate policy: %w", ErrAuthentication, err)
		}

		chains = slices.DeleteFunc(chains, func(chain []*x509.Certificate) bool {
			return !slices.ContainsFunc(callerChains, func(callerChain []*x509.Certificate) bool {
				return slices.EqualFunc(chain, callerChain, func(a, b *x509.Certificate) bool { return bytes.Equal(a.Raw, b.Raw) })
			})
		})
	}

	for _, chain := range chains {
		valid := true

		for _, cert := range chain {
			if len(cert.ExtKeyUsage) != 0 || len(cert.UnknownExtKeyUsage) != 0 {
				if !slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny) && !slices.ContainsFunc(cert.UnknownExtKeyUsage, func(oid asn1.ObjectIdentifier) bool { return oid.Equal(oidContentSigning) }) {
					valid = false
					break
				}
			}
		}

		if valid {
			return nil
		}
	}

	return fmt.Errorf("%w: certificate chain does not permit PIV content signing", ErrAuthentication)
}
