// Package sm implements NIST SP 800-73-5 Part 2 secure messaging, cipher suites
// CS2 (algorithm 27) and CS7 (algorithm 2E). It authenticates the card using an
// explicitly trusted certificate signer and protects complete commands above
// ISO 7816 framing.
//
// Open establishes a fresh P-256/AES-128 (CS2) or P-384/AES-256 (CS7) session
// over a selected PIV connection using an explicitly selected cipher suite.
// Pass the resulting Transport to card.New. Pairing and virtual contact interface
// operations belong to card and are never performed implicitly by this package.
// This one-pass protocol does not provide forward secrecy.
package sm

import "errors"

var (
	// ErrAuthentication reports an untrusted certificate or failed key confirmation.
	ErrAuthentication = errors.New("sm: card authentication failed")
	// ErrInvalidResponse reports malformed or unauthenticated secure messaging data.
	ErrInvalidResponse = errors.New("sm: invalid response")
	// ErrSessionExhausted means that the session must be replaced before more I/O.
	ErrSessionExhausted = errors.New("sm: encryption counter exhausted")
)
