package credential

import (
	"crypto/sha256"
	"fmt"

	"github.com/telesma-app/piv/protocol"
)

// VerifyOffCardKeyHistoryFile checks the exact retrieved file bytes against the
// SHA-256 digest in offCardCertURL (SP 800-73-5 Part 1, Sec. 3.3.3). The caller
// must authenticate the Key History object, including its URL, separately.
// Retrieval, DER parsing, and certificate validation are separate operations.
// Malformed URLs return protocol.ErrInvalidResponse; mismatches return ErrIntegrity.
func VerifyOffCardKeyHistoryFile(offCardCertURL string, data []byte) error {
	expected, err := protocol.ParseOffCardCertURL(offCardCertURL)
	if err != nil {
		return err
	}

	if sha256.Sum256(data) != expected {
		return fmt.Errorf("%w: off-card key history digest mismatch", ErrIntegrity)
	}

	return nil
}
