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
	"errors"
)

var (
	// ErrAuthentication reports invalid signatures, untrusted signers, expired
	// cards, or signed credential identifiers that do not match.
	ErrAuthentication = errors.New("piv: credential authentication failed")
	// ErrIntegrity reports an absent or altered data group or an off-card key
	// history file whose digest does not match its authenticated URL.
	ErrIntegrity = errors.New("piv: data-group integrity check failed")
)
