// Package credential authenticates PIV signed data without card I/O.
//
// Verification requires explicit trust roots, checks content-signing certificate
// paths, PIV certificate policy and extended key usage, and uses the current
// time in x509.VerifyOptions (or time.Now). It does not fetch intermediates,
// CRLs or OCSP responses. Revocation and application authorization remain the
// caller's responsibility. Successful signature verification does not prove
// possession of a card's private key or perform biometric comparison.
package credential

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/piv/protocol"
)

var (
	// ErrAuthentication reports invalid signatures, untrusted signers, expired
	// cards, or signed credential identifiers that do not match.
	ErrAuthentication = errors.New("piv: credential authentication failed")
	// ErrIntegrity reports an absent or altered data group or an off-card key
	// history file whose digest does not match its authenticated URL.
	ErrIntegrity = errors.New("piv: data-group integrity check failed")

	oidContentSigning = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 6, 7}
	oidContentPolicy  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 39}
)

// VerifyCHUID authenticates the original CHUID.Raw bytes, including unknown
// fields and original BER lengths, excluding only the signature TLV. It checks
// its detached CMS profile, certificate path and the card's expiration date.
// The final calendar date is valid through midnight at the start of the next
// UTC date. It returns the authenticated content-signing certificate.
//
// Roots must be supplied explicitly. Intermediates and other path constraints
// come from options. When KeyUsages is empty, verification uses the PIV content
// signing EKU instead of x509's TLS server default. CertificatePolicies defaults
// to the PIV content-signing policy; supplied policies add caller constraints.
// Revocation is not checked.
func VerifyCHUID(chuid protocol.CHUID, options x509.VerifyOptions) (*x509.Certificate, error) {
	signed, err := parseCMS(chuid.IssuerSignature)
	if err != nil {
		return nil, err
	}

	if signed.Content.Content != nil || len(signed.Signers) != 1 || len(signed.Digests) != 1 || signed.Signers[0].Version != 1 {
		return nil, fmt.Errorf("%w: CHUID requires detached content, one digest and one issuer/serial signer", ErrAuthentication)
	}

	certificate, err := cmsCertificate(signed, nil, true)
	if err != nil {
		return nil, err
	}

	var content []byte

	for data := chuid.Raw; len(data) != 0; {
		tag, _, rest, err := bertlv.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%w: malformed CHUID: %v", ErrAuthentication, err)
		}

		if tag != 0x3e {
			content = append(content, data[:len(data)-len(rest)]...)
		}

		data = rest
	}

	if _, err := verifyCMS(signed, certificate, content, oidCHUID, true); err != nil {
		return nil, err
	}

	if err := verifySigner(certificate, options); err != nil {
		return nil, err
	}

	now := options.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	if !now.Before(chuid.ExpirationDate.AddDate(0, 0, 1)) {
		return nil, fmt.Errorf("%w: card has expired", ErrAuthentication)
	}

	return certificate, nil
}

// VerifySecurityObject verifies the Security Object with the content-signing
// certificate returned by VerifyCHUID. The CMS must omit certificates and
// contain an LDS digest list matching every mapping entry. Every SignerInfo
// identifying signer must verify and use the LDS hash algorithm; at least one
// must be present. Both issuer/serial and subject-key identifiers are supported.
// Unrelated SignerInfos are not authenticated. A failed matching signature is
// an error even if another matching signature is valid.
// The returned digests are authenticated; use VerifyDataGroups to check data.
func VerifySecurityObject(object protocol.SecurityObjectData, signer *x509.Certificate, options x509.VerifyOptions) (protocol.LDSSecurityObject, error) {
	signed, err := parseCMS(object.SignedData)
	if err != nil {
		return protocol.LDSSecurityObject{}, err
	}

	if signed.Certificates.FullBytes != nil || signed.Content.Content == nil {
		return protocol.LDSSecurityObject{}, fmt.Errorf("%w: invalid Security Object CMS certificate or content field", ErrAuthentication)
	}

	// Earlier ICAO profiles used 1.3.27.1.1.1, including the public GSA card
	// fixtures. Both identify the same LDS syntax; the signed content-type
	// attribute must still match the exact OID present in this message.
	if !signed.Content.Type.Equal(oidLDS) && !signed.Content.Type.Equal(oidLDSLegacy) {
		return protocol.LDSSecurityObject{}, fmt.Errorf("%w: unexpected LDS content type", ErrAuthentication)
	}

	var signerHash crypto.Hash

	for _, si := range signed.Signers {
		matched, err := signerMatchesCertificate(si, signer)
		if err != nil {
			return protocol.LDSSecurityObject{}, err
		}

		if !matched {
			continue
		}

		if _, err := verifyCMSSigner(signed, si, signer, signed.Content.Content, signed.Content.Type, false); err != nil {
			return protocol.LDSSecurityObject{}, err
		}

		hash, err := digestAlgorithm(si.Digest)
		if err != nil {
			return protocol.LDSSecurityObject{}, err
		}

		if signerHash != 0 && signerHash != hash {
			return protocol.LDSSecurityObject{}, fmt.Errorf("%w: matching Security Object signers use different digest algorithms", ErrAuthentication)
		}

		signerHash = hash
	}

	if signerHash == 0 {
		return protocol.LDSSecurityObject{}, fmt.Errorf("%w: Security Object has no signature from the selected content signer", ErrAuthentication)
	}

	if err := verifySigner(signer, options); err != nil {
		return protocol.LDSSecurityObject{}, err
	}

	lds, err := protocol.ParseLDSSecurityObject(signed.Content.Content)
	if err != nil {
		return protocol.LDSSecurityObject{}, err
	}

	if signerHash != lds.HashAlgorithm || len(object.Mapping) != len(lds.Hashes) {
		return protocol.LDSSecurityObject{}, fmt.Errorf("%w: Security Object mapping or digest algorithm mismatch", ErrAuthentication)
	}

	for _, entry := range object.Mapping {
		if !slices.ContainsFunc(lds.Hashes, func(h protocol.DataGroupHash) bool { return h.DataGroup == entry.DataGroup }) {
			return protocol.LDSSecurityObject{}, fmt.Errorf("%w: mapped data group has no signed digest", ErrAuthentication)
		}
	}

	return lds, nil
}

// VerifyBiometric verifies a biometric record's detached CMS signature and
// binds its signed FASC-N and entryUUID attributes, plus the CBEFF header's
// FASC-N, to an authenticated CHUID. The same signer is used when the footer
// omits its certificate; a footer may contain a single different signer.
//
// This checks signature integrity and card binding, not biometric comparison.
// Biometric validity-period policy belongs to the caller: SP 800-76-2, Table
// 14, Note 5 makes its closing date advisory for biometric recollection.
func VerifyBiometric(data protocol.BiometricData, chuid protocol.CHUID, options x509.VerifyOptions) (*x509.Certificate, error) {
	chuidSigner, err := VerifyCHUID(chuid, options)
	if err != nil {
		return nil, err
	}

	signed, err := parseCMS(data.Signature)
	if err != nil {
		return nil, err
	}

	if signed.Content.Content != nil || len(signed.Signers) != 1 || len(signed.Digests) != 1 || signed.Signers[0].Version != 1 {
		return nil, fmt.Errorf("%w: biometric CMS requires detached content, one digest and one issuer/serial signer", ErrAuthentication)
	}

	certificate, err := cmsCertificate(signed, chuidSigner, false)
	if err != nil {
		return nil, err
	}

	if signed.Certificates.FullBytes != nil && bytes.Equal(certificate.RawSubjectPublicKeyInfo, chuidSigner.RawSubjectPublicKeyInfo) {
		return nil, fmt.Errorf("%w: biometric CMS must omit a certificate for the CHUID signing key", ErrAuthentication)
	}

	attrs, err := verifyCMS(signed, certificate, data.SignedData, oidBiometric, true)
	if err != nil {
		return nil, err
	}

	var fascn, guid []byte
	if err := attributeValue(attrs, oidFASCN, &fascn); err != nil {
		return nil, err
	}

	if err := attributeValue(attrs, oidEntryUUID, &guid); err != nil {
		return nil, err
	}

	if !bytes.Equal(fascn, chuid.FASCN[:]) || !bytes.Equal(guid, chuid.GUID[:]) || data.Header.FASCN != chuid.FASCN {
		return nil, fmt.Errorf("%w: biometric data belongs to a different card", ErrAuthentication)
	}

	if err := verifySigner(certificate, options); err != nil {
		return nil, err
	}

	return certificate, nil
}

// DataGroupError identifies the container whose authenticated digest could not
// be checked. It unwraps to ErrIntegrity.
type DataGroupError struct {
	ContainerID protocol.ContainerID
	Missing     bool
}

func (e *DataGroupError) Error() string {
	if e.Missing {
		return fmt.Sprintf("piv: data group container %04x is missing", uint16(e.ContainerID))
	}

	return fmt.Sprintf("piv: data group container %04x digest mismatch", uint16(e.ContainerID))
}

func (e *DataGroupError) Unwrap() error { return ErrIntegrity }

// VerifyDataGroups checks every mapped container against the authenticated LDS
// digest list returned by VerifySecurityObject. Data contains exact object
// contents returned by GetData, without the outer 53/7E/7F61 template; decoded
// or re-encoded objects are not equivalent. Extra containers are ignored.
// An absent container is an error, so this never silently verifies a subset.
func VerifyDataGroups(object protocol.SecurityObjectData, lds protocol.LDSSecurityObject, data map[protocol.ContainerID][]byte) error {
	for _, entry := range object.Mapping {
		content, ok := data[entry.ContainerID]
		if !ok {
			return &DataGroupError{ContainerID: entry.ContainerID, Missing: true}
		}

		for _, hash := range lds.Hashes {
			if hash.DataGroup == entry.DataGroup && !bytes.Equal(hash.Digest, digest(lds.HashAlgorithm, content)) {
				return &DataGroupError{ContainerID: entry.ContainerID}
			}
		}
	}

	return nil
}

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

// crypto/rsa reserves SaltLength=0 for automatic detection. Construct the
// deterministic EMSA-PSS encoding for the actual empty-salt case (RFC 8017,
// Sec. 9.1.1), using only public RSA operations.
func verifyPSSZeroSalt(key *rsa.PublicKey, hash crypto.Hash, hashed, signature []byte) error {
	if len(signature) != key.Size() {
		return rsa.ErrVerification
	}

	s := new(big.Int).SetBytes(signature)
	if s.Cmp(key.N) >= 0 {
		return rsa.ErrVerification
	}

	emBits := key.N.BitLen() - 1

	emLen := (emBits + 7) / 8
	if emLen < hash.Size()+2 {
		return rsa.ErrVerification
	}

	m := append(make([]byte, 8), hashed...)
	h := digest(hash, m)
	db := make([]byte, emLen-hash.Size()-1)

	db[len(db)-1] = 1
	for offset, counter := 0, uint32(0); offset < len(db); counter++ {
		input := append(bytes.Clone(h), binary.BigEndian.AppendUint32(nil, counter)...)

		mask := digest(hash, input)
		for _, b := range mask {
			if offset == len(db) {
				break
			}

			db[offset] ^= b
			offset++
		}
	}

	db[0] &= byte(0xff >> (8*emLen - emBits))
	expected := append(db, h...)
	expected = append(expected, 0xbc)

	actual := new(big.Int).Exp(s, big.NewInt(int64(key.E)), key.N)
	if actual.Cmp(new(big.Int).SetBytes(expected)) != 0 {
		return rsa.ErrVerification
	}

	return nil
}
