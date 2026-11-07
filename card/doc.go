// Package card provides owned PIV card sessions over initialized transports.
//
// New takes ownership of a transport on which PIV is already selected. Device
// serializes complete operations, including raw vendor exchanges, and owns the
// transport until Close. The caller must not use the transport independently
// after ownership transfers; the card's client remains private.
//
// ApplicationProperties returns an initial SELECT snapshot without I/O. New
// obtains it from transports that expose the result; NewWithApplicationProperties
// binds an explicit snapshot when an external wrapper does not expose it. The
// returned slices are read-only and remain available after Close.
//
// Waiting for an operation respects its context. Close prevents new operations,
// releases waiting callers, and closes the transport without acquiring the
// operation gate. Interrupting active I/O depends on the transport. A
// transport.DeviceInvalidatedError closes the session; subsequent operations
// return io.ErrClosedPipe. Cancellation before an operation starts preserves
// the session, and a completed response is not replaced by a later cancellation.
//
// Certificates lazily reads all 24 standard certificate slots and yields both
// successful and failed reads with their key references. Each read releases the
// operation gate before yielding. GetCertificateDER allows export without X.509
// parsing; GetKeyHistory separately reports retired keys and off-card locations.
// GetDiscovery reads the optional PIN Usage Policy without selecting a PIN or
// establishing a virtual contact interface.
// GetCHUID, GetCCC and GetPrintedInformation read typed card metadata without
// verifying its signatures or applying card-expiration policy. Object views may
// borrow their raw response bytes as documented by the protocol types.
//
// Verify and ResetSecurityStatus expose the VERIFY modes. VerifyPIN, ChangePIN,
// and UnblockPIN encode standard application PINs; ChangeReferenceData and
// ResetRetryCounter accept encoded values. Separate calls do not form an atomic
// authentication workflow. ReferenceStatus reports exact retry counts only from
// 63Cx; status 6983 remains an APDU error with an unknown retry count.
//
// VerifyPairingCode explicitly submits the eight-digit pairing code.
// CheckVCI separately checks current Discovery policy and pairing status
// over active NIST PIV secure messaging. Neither the secure messaging handshake
// nor CheckVCI submits a pairing code automatically. VCI status is not
// cached; the card evaluates its conditions for each protected command.
//
// GenerateAsymmetricKeyPair, PutData, and PutCertificate each authenticate the
// card administrator and perform the administrative command under one operation
// gate. They borrow an explicit AdministrationKey and do not retry. A bad or
// malformed administration proof invalidates the session. Generation and
// certificate installation are independent operations; a failed installation
// does not undo key generation.
//
// ExchangeAdministration extends that workflow to one raw vendor command and
// returns its final status word without interpretation. Its optional
// AuthenticationSource runs before the gate; management authentication, VERIFY,
// and the command then run together. The operation owns and clears successfully
// supplied authentication data. The vendor command must leave PIV selected.
//
// PrivateKey binds a slot and its public key without I/O. Sign, Decrypt and ECDH
// take an explicit context and optional AuthenticationSource. The source supplies
// a VERIFY reference and encoded data before the operation gate; VERIFY and the
// private-key command then form one workflow. The operation owns and clears the
// supplied authentication data. PINAuthentication encodes a standard PIN for an
// explicitly selected reference. Signer and Decrypter adapt the key to standard
// crypto interfaces with a caller-supplied context.
//
// Sign verifies every signature against the bound public key. Decrypt supports
// RSA OAEP and PKCS #1 v1.5 with host-side padding removal. ECDH supports P-256
// and P-384 key-management keys and returns the fixed-width shared secret without
// applying a KDF. Decrypt and ECDH do not prove that the slot's private key still
// matches the binding. Successful plaintext and shared-secret buffers belong to
// the caller.
//
// A github.com/telesma-app/iso7816/scp11 channel may be passed to New to protect
// these same operations with GlobalPlatform SCP11b. Establish the channel using a
// previously trusted card key before creating Device; certificate retrieval
// alone does not establish trust. Unauthenticated status words invalidate that
// channel, including unsigned errors returned by some card firmware. No
// plaintext downgrade or reconnect is performed. This channel profile is
// distinct from the NIST SP 800-73 secure messaging suites 27 and 2E.
//
// Device does not cache certificates, authentication state, PINs, or
// administration keys. Application discovery and certificate trust evaluation
// belong to the caller.
package card
