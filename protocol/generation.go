package protocol

// GenerateAsymmetricKeyPairRequest selects the key reference and control
// reference template for GENERATE ASYMMETRIC KEY PAIR (SP 800-73-5 Part 2,
// Section 3.3.2). Generation replaces any existing private key in Key.
type GenerateAsymmetricKeyPairRequest struct {
	Key       KeyReference
	Algorithm Algorithm

	// Parameter is the algorithm-specific value of tag 81. Nil omits the tag.
	// For RSA it is an optional public exponent encoded big-endian; ECC has
	// no parameter (SP 800-73-5 Part 1, Table 6). The caller supplies its encoding.
	// The value is borrowed for the call and must not be modified concurrently.
	Parameter []byte
}
