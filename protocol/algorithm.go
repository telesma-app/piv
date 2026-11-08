package protocol

// Algorithm is a PIV algorithm identifier. It selects an algorithm and key size
// or a secure messaging cipher suite. The standard asymmetric identifiers also
// serve as generation mechanism identifiers (SP 800-73-5 Part 1, Sec. 5.2 and
// Table 6; SP 800-78-5, Table 9).
type Algorithm byte

const (
	// TripleDESLegacy and TripleDES both identify three-key Triple DES in ECB
	// mode. Both identifiers are deprecated by SP 800-78-5. Zero selects the
	// legacy identifier explicitly; it does not request algorithm negotiation.
	TripleDESLegacy Algorithm = 0x00
	TripleDES       Algorithm = 0x03
	RSA3072         Algorithm = 0x05
	RSA1024         Algorithm = 0x06
	RSA2048         Algorithm = 0x07
	AES128          Algorithm = 0x08
	AES192          Algorithm = 0x0a
	AES256          Algorithm = 0x0c
	ECCP256         Algorithm = 0x11
	ECCP384         Algorithm = 0x14
	CipherSuite2    Algorithm = 0x27
	CipherSuite7    Algorithm = 0x2e

	// These common extension identifiers are not defined by NIST PIV. Devices
	// must support the corresponding extension and use these wire values.
	// CanoKey defaults to these values but permits reconfiguration:
	// https://docs.canokeys.org/development/protocols/piv/#21-algorithm-ids
	ECCP521 Algorithm = 0x15
	RSA4096 Algorithm = 0x16
	Ed25519 Algorithm = 0xe0
	X25519  Algorithm = 0xe1
)
