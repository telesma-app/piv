package sm

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"

	"github.com/telesma-app/bertlv"
)

var oidRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}

// CardCertificate contains the card identity authenticated during Open. GUID is
// the 16-byte Card UUID in the CVC Subject Identifier (SP 800-73-5 Part 2,
// Table 19). PublicKey is the card's static ECDH key, whose possession is proved
// by key confirmation. Raw is the exact BER-TLV CVC, including tag 7F21 and its
// original length encoding.
type CardCertificate struct {
	Raw       []byte
	GUID      [16]byte
	PublicKey *ecdh.PublicKey
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

func verifyCertificate(suite cipherSuite, raw []byte, trust Trust) (CardCertificate, error) {
	card, err := parseCertificate(suite, raw, false)
	if err != nil {
		return CardCertificate{}, err
	}

	issuer := trust.IssuerID

	key := trust.PublicKey
	if len(trust.IntermediateCVC) != 0 {
		intermediate, err := parseCertificate(suite, trust.IntermediateCVC, true)
		if err != nil {
			return CardCertificate{}, err
		}

		if intermediate.issuer != issuer {
			return CardCertificate{}, fmt.Errorf("%w: intermediate CVC issuer mismatch", ErrAuthentication)
		}

		if err := intermediate.verify(suite, key, true); err != nil {
			return CardCertificate{}, err
		}

		copy(issuer[:], intermediate.subject)

		public, err := ecdsa.ParseUncompressedPublicKey(suite.signingCurve, intermediate.publicKey.Bytes())
		if err != nil {
			return CardCertificate{}, fmt.Errorf("%w: intermediate public key: %v", ErrAuthentication, err)
		}

		key = public
	}

	if card.issuer != issuer {
		return CardCertificate{}, fmt.Errorf("%w: card CVC issuer mismatch", ErrAuthentication)
	}

	if err := card.verify(suite, key, false); err != nil {
		return CardCertificate{}, err
	}

	return CardCertificate{Raw: raw, GUID: [16]byte(card.subject), PublicKey: card.publicKey}, nil
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
