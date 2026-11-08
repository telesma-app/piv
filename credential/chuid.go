package credential

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/piv/protocol"
)

// VerifyCHUID authenticates the CHUID signature (SP 800-73-5 Part 1,
// Sec. 3.1.2.1) over the original CHUID.Raw bytes, including unknown
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
