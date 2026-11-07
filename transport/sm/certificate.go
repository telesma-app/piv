package sm

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"slices"

	"github.com/telesma-app/piv/internal/bertlv"
)

var (
	oidRSASHA256      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
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

type certificate struct {
	signed     []byte
	issuer     [8]byte
	subject    []byte
	publicKey  *ecdh.PublicKey
	algorithm  asn1.ObjectIdentifier
	parameters asn1.RawValue
	signature  []byte
}

func verifyCertificate(suite cipherSuite, raw []byte, trust Trust) (*ecdh.PublicKey, error) {
	card, err := parseCertificate(suite, raw, false)
	if err != nil {
		return nil, err
	}

	issuer := trust.IssuerID

	key := trust.PublicKey
	if len(trust.IntermediateCVC) != 0 {
		intermediate, err := parseCertificate(suite, trust.IntermediateCVC, true)
		if err != nil {
			return nil, err
		}

		if intermediate.issuer != issuer {
			return nil, fmt.Errorf("%w: intermediate CVC issuer mismatch", ErrAuthentication)
		}

		if err := intermediate.verify(suite, key, true); err != nil {
			return nil, err
		}

		copy(issuer[:], intermediate.subject)

		public, err := ecdsa.ParseUncompressedPublicKey(suite.signingCurve, intermediate.publicKey.Bytes())
		if err != nil {
			return nil, fmt.Errorf("%w: intermediate public key: %v", ErrAuthentication, err)
		}

		key = public
	}

	if card.issuer != issuer {
		return nil, fmt.Errorf("%w: card CVC issuer mismatch", ErrAuthentication)
	}

	if err := card.verify(suite, key, false); err != nil {
		return nil, err
	}

	return card.publicKey, nil
}

func (c certificate) verify(suite cipherSuite, key crypto.PublicKey, intermediate bool) error {
	if intermediate {
		public, ok := key.(*rsa.PublicKey)
		if !ok || !c.algorithm.Equal(oidRSASHA256) || !bytes.Equal(c.parameters.FullBytes, []byte{5, 0}) {
			return fmt.Errorf("%w: intermediate CVC requires RSA with SHA-256", ErrAuthentication)
		}

		digest := sha256.Sum256(c.signed)
		if err := rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], c.signature); err != nil {
			return fmt.Errorf("%w: intermediate CVC signature: %w", ErrAuthentication, err)
		}

		return nil
	}

	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != suite.signingCurve || !c.algorithm.Equal(suite.signatureOID) || len(c.parameters.FullBytes) != 0 {
		return fmt.Errorf("%w: CVC signature does not match cipher suite %02X", ErrAuthentication, byte(suite.algorithm))
	}

	h := suite.newHash()
	h.Write(c.signed)

	if !ecdsa.VerifyASN1(public, h.Sum(nil), c.signature) {
		return fmt.Errorf("%w: card CVC signature mismatch", ErrAuthentication)
	}

	return nil
}

func parseCertificate(suite cipherSuite, raw []byte, intermediate bool) (certificate, error) {
	tag, body, rest, err := bertlv.Parse(raw)
	if err != nil || tag != 0x7f21 || len(rest) != 0 {
		return certificate{}, fmt.Errorf("%w: invalid CVC envelope", ErrInvalidResponse)
	}

	signed := body

	var (
		c     certificate
		value []byte
	)
	if value, body, err = certificateField(body, 0x5f29); err != nil || !bytes.Equal(value, []byte{0x80}) {
		return certificate{}, fmt.Errorf("%w: invalid CVC credential profile", ErrInvalidResponse)
	}

	if value, body, err = certificateField(body, 0x42); err != nil || len(value) != 8 {
		return certificate{}, fmt.Errorf("%w: invalid CVC issuer", ErrInvalidResponse)
	}

	copy(c.issuer[:], value)

	subjectLength, role := 16, byte(0)
	if intermediate {
		subjectLength, role = 8, 0x12
	}

	if value, body, err = certificateField(body, 0x5f20); err != nil || len(value) != subjectLength {
		return certificate{}, fmt.Errorf("%w: invalid CVC subject", ErrInvalidResponse)
	}

	c.subject = value

	if value, body, err = certificateField(body, 0x7f49); err != nil {
		return certificate{}, err
	}

	oid, keyData, err := certificateField(value, 6)
	if err != nil || !bytes.Equal(oid, suite.curveOID) {
		return certificate{}, fmt.Errorf("%w: CVC public key does not match cipher suite %02X", ErrAuthentication, byte(suite.algorithm))
	}

	point, keyRest, err := certificateField(keyData, 0x86)
	if err != nil || len(keyRest) != 0 {
		return certificate{}, fmt.Errorf("%w: invalid CVC public-key object", ErrInvalidResponse)
	}

	c.publicKey, err = suite.curve.NewPublicKey(point)
	if err != nil {
		return certificate{}, fmt.Errorf("%w: invalid CVC public point: %v", ErrAuthentication, err)
	}

	if intermediate {
		// SHA-1 is used only for the identifier specified by Table 20, not as
		// the signature hash or a trust decision.
		identifier := sha1.Sum(point)
		if !bytes.Equal(c.subject, identifier[:8]) {
			return certificate{}, fmt.Errorf("%w: intermediate CVC subject identifier mismatch", ErrAuthentication)
		}
	}

	if value, body, err = certificateField(body, 0x5f4c); err != nil || !bytes.Equal(value, []byte{role}) {
		return certificate{}, fmt.Errorf("%w: invalid CVC role", ErrInvalidResponse)
	}

	// Keep the exact signed BER bytes, including their original length
	// encodings. Re-encoding parsed fields would authenticate different data.
	c.signed = signed[:len(signed)-len(body)]
	if value, body, err = certificateField(body, 0x5f37); err != nil || len(body) != 0 {
		return certificate{}, fmt.Errorf("%w: invalid CVC signature object", ErrInvalidResponse)
	}

	var signature struct {
		Algorithm struct {
			OID        asn1.ObjectIdentifier
			Parameters asn1.RawValue `asn1:"optional"`
		}
		Value asn1.BitString
	}

	rest, err = asn1.Unmarshal(value, &signature)
	if err != nil || len(rest) != 0 || signature.Value.BitLength != len(signature.Value.Bytes)*8 {
		return certificate{}, fmt.Errorf("%w: invalid CVC DigitalSignature", ErrInvalidResponse)
	}
	// The DigitalSignature is DER. In particular, struct decoding alone
	// permits extra SEQUENCE members, which are outside this schema.
	encoded, err := asn1.Marshal(signature)
	if err != nil || !bytes.Equal(encoded, value) {
		return certificate{}, fmt.Errorf("%w: noncanonical CVC DigitalSignature", ErrInvalidResponse)
	}

	c.algorithm = signature.Algorithm.OID
	c.parameters = signature.Algorithm.Parameters
	c.signature = signature.Value.Bytes

	return c, nil
}

func certificateField(data []byte, expected uint32) (value, rest []byte, err error) {
	tag, value, rest, err := bertlv.Parse(data)
	if err != nil || tag != expected {
		return nil, nil, fmt.Errorf("%w: expected CVC tag %X", ErrInvalidResponse, expected)
	}

	return value, rest, nil
}
