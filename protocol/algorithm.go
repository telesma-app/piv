package protocol

// Algorithm is a PIV algorithm identifier (SP 800-73-5 Part 1, Sec. 5.2;
// SP 800-78-5, Table 9). It selects an algorithm and key size or a secure
// messaging cipher suite. The asymmetric identifiers also serve as generation
// mechanism identifiers (SP 800-73-5 Part 1, Table 6).
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
)
