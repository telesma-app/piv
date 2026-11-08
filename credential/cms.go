package credential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"slices"
)

var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSignerDN      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 5}
	oidFASCN         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 6}
	oidEntryUUID     = asn1.ObjectIdentifier{1, 3, 6, 1, 1, 16, 4}
	oidCHUID         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 1}
	oidBiometric     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 2}
	oidLDS           = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	oidLDSLegacy     = asn1.ObjectIdentifier{1, 3, 27, 1, 1, 1}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidRSA           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRSA256        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSA384        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidECDSA256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSA384      = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
)

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapsulatedContentInfo struct {
	Type    asn1.ObjectIdentifier
	Content []byte `asn1:"optional,explicit,tag:0"`
}

type signedData struct {
	Version      int
	Digests      []pkix.AlgorithmIdentifier `asn1:"set"`
	Content      encapsulatedContentInfo
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	CRLs         asn1.RawValue `asn1:"optional,tag:1"`
	Signers      []signerInfo  `asn1:"set"`
}

type signerInfo struct {
	Raw       asn1.RawContent
	Version   int
	SID       asn1.RawValue
	Digest    pkix.AlgorithmIdentifier
	Attrs     asn1.RawValue `asn1:"optional,tag:0"`
	Algorithm pkix.AlgorithmIdentifier
	Signature []byte
	Unsigned  asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

func decode(data []byte, value any) error {
	rest, err := asn1.Unmarshal(data, value)
	if err != nil {
		return fmt.Errorf("%w: CMS ASN.1: %v", ErrAuthentication, err)
	}

	if len(rest) != 0 {
		return fmt.Errorf("%w: trailing CMS ASN.1 data", ErrAuthentication)
	}

	return nil
}

// sequenceFields also detects extra fields that encoding/asn1 would otherwise
// ignore after the last known member of a SEQUENCE.
func sequenceFields(data []byte) ([]asn1.RawValue, error) {
	var sequence asn1.RawValue
	if err := decode(data, &sequence); err != nil {
		return nil, err
	}

	if sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, fmt.Errorf("%w: expected ASN.1 sequence", ErrAuthentication)
	}

	var fields []asn1.RawValue

	for data = sequence.Bytes; len(data) != 0; {
		var field asn1.RawValue

		rest, err := asn1.Unmarshal(data, &field)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed ASN.1 field: %v", ErrAuthentication, err)
		}

		fields = append(fields, field)
		data = rest
	}

	return fields, nil
}

func parseCMS(data []byte) (signedData, error) {
	var info contentInfo
	if err := decode(data, &info); err != nil {
		return signedData{}, err
	}

	fields, err := sequenceFields(data)
	if err != nil || len(fields) != 2 || !info.Type.Equal(oidSignedData) {
		return signedData{}, fmt.Errorf("%w: expected CMS SignedData", ErrAuthentication)
	}

	var signed signedData
	if err := decode(info.Content.Bytes, &signed); err != nil {
		return signedData{}, err
	}

	fields, err = sequenceFields(info.Content.Bytes)

	expected := 4
	if signed.Certificates.FullBytes != nil {
		expected++
	}

	if signed.CRLs.FullBytes != nil {
		expected++
	}

	if err != nil || len(fields) != expected || signed.Version != 3 || len(signed.Signers) == 0 || len(signed.Digests) == 0 || signed.CRLs.FullBytes != nil {
		return signedData{}, fmt.Errorf("%w: invalid PIV SignedData profile", ErrAuthentication)
	}

	contentFields, err := sequenceFields(fields[2].FullBytes)
	if err != nil || len(contentFields) < 1 || len(contentFields) > 2 {
		return signedData{}, fmt.Errorf("%w: invalid CMS encapsulated content", ErrAuthentication)
	}

	for _, algorithm := range signed.Digests {
		if _, err := digestAlgorithm(algorithm); err != nil {
			return signedData{}, err
		}
	}

	var digestSet asn1.RawValue
	if err := decode(fields[1].FullBytes, &digestSet); err != nil {
		return signedData{}, err
	}

	for data := digestSet.Bytes; len(data) != 0; {
		var algorithm asn1.RawValue

		rest, err := asn1.Unmarshal(data, &algorithm)
		if err != nil {
			return signedData{}, fmt.Errorf("%w: malformed digest set: %v", ErrAuthentication, err)
		}

		if err := checkAlgorithmEncoding(algorithm.FullBytes); err != nil {
			return signedData{}, err
		}

		data = rest
	}

	for _, si := range signed.Signers {
		signerFields, err := sequenceFields(si.Raw)

		expected = 5
		if si.Attrs.FullBytes != nil {
			expected++
		}

		if si.Unsigned.FullBytes != nil {
			expected++
		}

		issuerSID := si.Version == 1 && si.SID.Class == asn1.ClassUniversal && si.SID.Tag == asn1.TagSequence && si.SID.IsCompound

		keyID := si.Version == 3 && si.SID.Class == asn1.ClassContextSpecific && si.SID.Tag == 0 && !si.SID.IsCompound && len(si.SID.Bytes) != 0
		if err != nil || len(signerFields) != expected || (!issuerSID && !keyID) {
			return signedData{}, fmt.Errorf("%w: invalid PIV SignerInfo profile", ErrAuthentication)
		}

		if _, err := digestAlgorithm(si.Digest); err != nil {
			return signedData{}, err
		}

		if !slices.ContainsFunc(signed.Digests, func(algorithm pkix.AlgorithmIdentifier) bool { return algorithm.Algorithm.Equal(si.Digest.Algorithm) }) {
			return signedData{}, fmt.Errorf("%w: signer digest is absent from SignedData digest set", ErrAuthentication)
		}

		if issuerSID {
			if _, err := issuerAndSerial(si); err != nil {
				return signedData{}, err
			}
		}

		if err := checkAlgorithmEncoding(signerFields[2].FullBytes); err != nil {
			return signedData{}, err
		}

		algorithmIndex := 3
		if si.Attrs.FullBytes != nil {
			algorithmIndex++
		}

		if err := checkAlgorithmEncoding(signerFields[algorithmIndex].FullBytes); err != nil {
			return signedData{}, err
		}
	}

	return signed, nil
}

func checkAlgorithmEncoding(data []byte) error {
	fields, err := sequenceFields(data)
	if err != nil {
		return err
	}

	if len(fields) < 1 || len(fields) > 2 || fields[0].Class != asn1.ClassUniversal || fields[0].Tag != asn1.TagOID {
		return fmt.Errorf("%w: malformed AlgorithmIdentifier", ErrAuthentication)
	}

	return nil
}

func cmsCertificate(signed signedData, external *x509.Certificate, requireEmbedded bool) (*x509.Certificate, error) {
	certificate := external

	if signed.Certificates.FullBytes != nil {
		var raw asn1.RawValue
		if err := decode(signed.Certificates.Bytes, &raw); err != nil {
			return nil, err
		}

		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence {
			return nil, fmt.Errorf("%w: invalid CMS certificate", ErrAuthentication)
		}

		var err error

		certificate, err = x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: CMS certificate: %w", ErrAuthentication, err)
		}
	} else if requireEmbedded {
		return nil, fmt.Errorf("%w: missing CHUID content-signing certificate", ErrAuthentication)
	}

	if certificate == nil {
		return nil, fmt.Errorf("%w: missing content-signing certificate", ErrAuthentication)
	}

	matched, err := signerMatchesCertificate(signed.Signers[0], certificate)
	if err != nil {
		return nil, err
	}

	if !matched {
		return nil, fmt.Errorf("%w: CMS signer identifier does not match certificate", ErrAuthentication)
	}

	return certificate, nil
}

type issuerAndSerialNumber struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

func issuerAndSerial(si signerInfo) (issuerAndSerialNumber, error) {
	var sid issuerAndSerialNumber
	if err := decode(si.SID.FullBytes, &sid); err != nil {
		return issuerAndSerialNumber{}, err
	}

	fields, err := sequenceFields(si.SID.FullBytes)
	if err != nil || len(fields) != 2 || sid.Issuer.Class != asn1.ClassUniversal || sid.Issuer.Tag != asn1.TagSequence || !sid.Issuer.IsCompound {
		return issuerAndSerialNumber{}, fmt.Errorf("%w: malformed CMS issuer/serial signer identifier", ErrAuthentication)
	}

	return sid, nil
}

func signerMatchesCertificate(si signerInfo, certificate *x509.Certificate) (bool, error) {
	if si.Version == 3 {
		return bytes.Equal(si.SID.Bytes, certificate.SubjectKeyId), nil
	}

	sid, err := issuerAndSerial(si)
	if err != nil {
		return false, err
	}

	return bytes.Equal(sid.Issuer.FullBytes, certificate.RawIssuer) && sid.Serial.Cmp(certificate.SerialNumber) == 0, nil
}

func signedAttributes(raw asn1.RawValue) (map[string]asn1.RawValue, []byte, error) {
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return nil, nil, fmt.Errorf("%w: missing signed attributes", ErrAuthentication)
	}

	attrs := make(map[string]asn1.RawValue)

	var previous []byte

	for data := raw.Bytes; len(data) != 0; {
		var value asn1.RawValue

		rest, err := asn1.Unmarshal(data, &value)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: malformed signed attributes: %v", ErrAuthentication, err)
		}

		if previous != nil && bytes.Compare(previous, value.FullBytes) > 0 {
			return nil, nil, fmt.Errorf("%w: signed attributes are not DER ordered", ErrAuthentication)
		}

		previous, data = value.FullBytes, rest

		var attr attribute
		if err := decode(value.FullBytes, &attr); err != nil {
			return nil, nil, err
		}

		fields, err := sequenceFields(value.FullBytes)
		if err != nil || len(fields) != 2 || attr.Values.Class != asn1.ClassUniversal || attr.Values.Tag != asn1.TagSet || !attr.Values.IsCompound {
			return nil, nil, fmt.Errorf("%w: malformed CMS attribute", ErrAuthentication)
		}

		if _, exists := attrs[attr.Type.String()]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate signed attribute %s", ErrAuthentication, attr.Type)
		}

		attrs[attr.Type.String()] = attr.Values
	}
	// RFC 5652, Sec. 5.4: authenticate the exact original DER encoding with
	// the universal SET tag replacing the IMPLICIT context-specific tag.
	signed := bytes.Clone(raw.FullBytes)
	signed[0] = 0x31

	return attrs, signed, nil
}

func attributeValue(attrs map[string]asn1.RawValue, oid asn1.ObjectIdentifier, out any) error {
	value, ok := attrs[oid.String()]
	if !ok {
		return fmt.Errorf("%w: missing signed attribute %s", ErrAuthentication, oid)
	}

	return decode(value.Bytes, out)
}

func verifyCMS(signed signedData, certificate *x509.Certificate, content []byte, contentType asn1.ObjectIdentifier, requireDN bool) (map[string]asn1.RawValue, error) {
	return verifyCMSSigner(signed, signed.Signers[0], certificate, content, contentType, requireDN)
}

func verifyCMSSigner(signed signedData, si signerInfo, certificate *x509.Certificate, content []byte, contentType asn1.ObjectIdentifier, requireDN bool) (map[string]asn1.RawValue, error) {
	if !signed.Content.Type.Equal(contentType) {
		return nil, fmt.Errorf("%w: unexpected CMS content type", ErrAuthentication)
	}

	attrs, signedBytes, err := signedAttributes(si.Attrs)
	if err != nil {
		return nil, err
	}

	var typ asn1.ObjectIdentifier
	if err := attributeValue(attrs, oidContentType, &typ); err != nil {
		return nil, err
	}

	if !typ.Equal(contentType) {
		return nil, fmt.Errorf("%w: signed content-type attribute mismatch", ErrAuthentication)
	}

	var expected []byte
	if err := attributeValue(attrs, oidMessageDigest, &expected); err != nil {
		return nil, err
	}

	hash, err := digestAlgorithm(si.Digest)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(expected, digest(hash, content)) {
		return nil, fmt.Errorf("%w: CMS message digest mismatch", ErrAuthentication)
	}

	if requireDN {
		var name asn1.RawValue
		if err := attributeValue(attrs, oidSignerDN, &name); err != nil {
			return nil, err
		}

		if !bytes.Equal(name.FullBytes, certificate.RawSubject) {
			return nil, fmt.Errorf("%w: pivSigner-DN does not match certificate subject", ErrAuthentication)
		}
	}

	if err := verifySignature(certificate, hash, si.Algorithm, digest(hash, signedBytes), si.Signature); err != nil {
		return nil, fmt.Errorf("%w: CMS signature: %w", ErrAuthentication, err)
	}

	return attrs, nil
}

func digestAlgorithm(algorithm pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	if p := algorithm.Parameters.FullBytes; len(p) != 0 && !bytes.Equal(p, asn1.NullBytes) {
		return 0, fmt.Errorf("%w: invalid digest parameters", ErrAuthentication)
	}

	switch {
	case algorithm.Algorithm.Equal(oidSHA256):
		return crypto.SHA256, nil
	case algorithm.Algorithm.Equal(oidSHA384):
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("%w: unsupported PIV digest algorithm %s", ErrAuthentication, algorithm.Algorithm)
	}
}

func digest(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA256:
		hash := sha256.Sum256(data)
		return hash[:]
	case crypto.SHA384:
		hash := sha512.Sum384(data)
		return hash[:]
	default:
		panic("unsupported PIV digest algorithm")
	}
}

func verifySignature(certificate *x509.Certificate, hash crypto.Hash, algorithm pkix.AlgorithmIdentifier, digest, signature []byte) error {
	// SP 800-78-5, Table 2 defines content-signing key/hash combinations,
	// independently of the card's private-key command algorithm identifiers.
	switch key := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if bits := key.N.BitLen(); bits != 2048 && bits != 3072 && bits != 4096 {
			return fmt.Errorf("unsupported PIV content-signing RSA key size")
		}
	case *ecdsa.PublicKey:
		supported := key.Curve == elliptic.P256() && hash == crypto.SHA256 ||
			key.Curve == elliptic.P384() && hash == crypto.SHA384
		if !supported {
			return fmt.Errorf("unsupported PIV content-signing curve/hash combination")
		}
	default:
		return fmt.Errorf("unsupported PIV content-signing public key")
	}

	switch {
	case algorithm.Algorithm.Equal(oidRSA), algorithm.Algorithm.Equal(oidRSA256), algorithm.Algorithm.Equal(oidRSA384):
		if !algorithm.Algorithm.Equal(oidRSA) && ((hash == crypto.SHA256) != algorithm.Algorithm.Equal(oidRSA256)) {
			return fmt.Errorf("signature and digest algorithms disagree")
		}

		if p := algorithm.Parameters.FullBytes; len(p) != 0 && !bytes.Equal(p, asn1.NullBytes) {
			return fmt.Errorf("invalid RSA signature parameters")
		}

		key, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA signature with non-RSA certificate")
		}

		return rsa.VerifyPKCS1v15(key, hash, digest, signature)
	case algorithm.Algorithm.Equal(oidRSAPSS):
		var params struct {
			Hash    pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
			MGF     pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
			Salt    int                      `asn1:"optional,explicit,tag:2,default:20"`
			Trailer int                      `asn1:"optional,explicit,tag:3,default:1"`
		}
		if err := decode(algorithm.Parameters.FullBytes, &params); err != nil {
			return err
		}

		fields, err := sequenceFields(algorithm.Parameters.FullBytes)
		if err != nil || len(fields) < 2 || len(fields) > 4 {
			return fmt.Errorf("invalid RSA-PSS parameter sequence")
		}

		if err := checkAlgorithmEncoding(params.MGF.Parameters.FullBytes); err != nil {
			return err
		}

		mgfHash := pkix.AlgorithmIdentifier{}
		if err := decode(params.MGF.Parameters.FullBytes, &mgfHash); err != nil {
			return err
		}

		pssHash, err := digestAlgorithm(params.Hash)
		if err != nil {
			return err
		}

		maskHash, err := digestAlgorithm(mgfHash)
		if err != nil {
			return err
		}

		if pssHash != hash || maskHash != hash || !params.MGF.Algorithm.Equal(oidMGF1) || params.Salt < 0 || params.Salt > hash.Size() || params.Trailer != 1 {
			return fmt.Errorf("invalid PIV RSA-PSS parameters")
		}

		key, ok := certificate.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA-PSS signature with non-RSA certificate")
		}
		// SaltLength=0 means auto-detection in crypto/rsa, whereas CMS means
		// an exactly empty salt. Verify its encoded length explicitly below.
		if params.Salt == 0 {
			return verifyPSSZeroSalt(key, hash, digest, signature)
		}

		return rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{SaltLength: params.Salt, Hash: hash})
	case algorithm.Algorithm.Equal(oidECDSA256), algorithm.Algorithm.Equal(oidECDSA384):
		if ((hash == crypto.SHA256) != algorithm.Algorithm.Equal(oidECDSA256)) || len(algorithm.Parameters.FullBytes) != 0 {
			return fmt.Errorf("invalid ECDSA signature algorithm or parameters")
		}

		key, ok := certificate.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ECDSA signature with non-ECDSA certificate")
		}

		if !ecdsa.VerifyASN1(key, digest, signature) {
			return fmt.Errorf("invalid ECDSA signature")
		}

		return nil
	default:
		return fmt.Errorf("unsupported PIV signature algorithm %s", algorithm.Algorithm)
	}
}
