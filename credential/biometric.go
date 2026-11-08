package credential

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// VerifyBiometric verifies a biometric record's detached CMS signature
// (SP 800-76-2, Sec. 9.3) and binds its signed FASC-N and entryUUID attributes,
// plus the CBEFF header's FASC-N, to an authenticated CHUID.
// The same signer is used when the footer
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
