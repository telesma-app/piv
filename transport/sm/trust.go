package sm

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"
)

var (
	oidContentSigning = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 7}
	oidExtendedUsage  = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// Trust identifies a signer obtained from a trusted source, not from the
// unauthenticated handshake. IssuerID is the leftmost eight bytes of the
// signer's X.509 subjectKeyIdentifier. PublicKey is a P-256 (CS2) or P-384 (CS7)
// ECDSA key for a direct card CVC, or an RSA key when IntermediateCVC is supplied.
// The optional intermediate is the exact BER-TLV certificate specified in Table 20 of
// SP 800-73-5 Part 2. Its issuer and signature are checked during Open.
//
// The caller must not modify these values while Open is running.
type Trust struct {
	IssuerID        [8]byte
	PublicKey       crypto.PublicKey
	IntermediateCVC []byte
}

// TrustFromCertificate validates an X.509 PIV content-signing certificate and
// builds trust for Open. Roots must be provided explicitly; system roots are
// never used. Other path-validation options, including CurrentTime and
// Intermediates, are honored. KeyUsages is replaced with ExtKeyUsageAny because
// the PIV content-signing EKU is checked explicitly here.
//
// The certificate requires the digitalSignature key usage, PIV content-signing
// EKU (2.16.840.1.101.3.6.7), and a subjectKeyIdentifier of at least eight bytes.
// intermediateCVC is optional and is borrowed until Open completes.
func TrustFromCertificate(cert *x509.Certificate, options x509.VerifyOptions, intermediateCVC []byte) (Trust, error) {
	if options.Roots == nil {
		return Trust{}, fmt.Errorf("%w: explicit content-signing roots required", ErrAuthentication)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return Trust{}, fmt.Errorf("%w: content signer lacks digitalSignature usage", ErrAuthentication)
	}

	contentSigning := false

	for _, usage := range cert.UnknownExtKeyUsage {
		if usage.Equal(oidContentSigning) {
			contentSigning = true
			break
		}
	}

	if !contentSigning {
		return Trust{}, fmt.Errorf("%w: content signer lacks PIV content-signing EKU", ErrAuthentication)
	}

	if len(cert.SubjectKeyId) < 8 {
		return Trust{}, fmt.Errorf("%w: content signer subjectKeyIdentifier is too short", ErrAuthentication)
	}

	options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}

	chains, err := cert.Verify(options)
	if err != nil {
		return Trust{}, fmt.Errorf("%w: validate content signer: %w", ErrAuthentication, err)
	}
	// x509.Verify cannot request an unrecognized EKU. ExtKeyUsageAny checks
	// the paths; enforce the content-signing restriction across each candidate
	// path here, including restrictions imposed by intermediate and root CAs.
	allowed := slices.ContainsFunc(chains, contentSigningChain)

	if !allowed {
		return Trust{}, fmt.Errorf("%w: certificate path excludes PIV content signing", ErrAuthentication)
	}

	var trust Trust
	copy(trust.IssuerID[:], cert.SubjectKeyId[:8])
	trust.PublicKey = cert.PublicKey
	trust.IntermediateCVC = intermediateCVC

	return trust, nil
}

func contentSigningChain(chain []*x509.Certificate) bool {
	for _, cert := range chain {
		constrained := false

		for _, extension := range cert.Extensions {
			if extension.Id.Equal(oidExtendedUsage) {
				constrained = true
				break
			}
		}

		if !constrained {
			continue
		}

		allowed := slices.Contains(cert.ExtKeyUsage, x509.ExtKeyUsageAny)

		for _, usage := range cert.UnknownExtKeyUsage {
			if usage.Equal(oidContentSigning) {
				allowed = true
				break
			}
		}

		if !allowed {
			return false
		}
	}

	return true
}
