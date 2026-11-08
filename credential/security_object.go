package credential

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"slices"

	"github.com/telesma-app/piv/protocol"
)

// VerifySecurityObject verifies the Security Object (SP 800-73-5 Part 1,
// Sec. 3.1.7) with the content-signing certificate returned by VerifyCHUID.
// The CMS must omit certificates and
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
