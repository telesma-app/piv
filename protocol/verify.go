package protocol

// VerifyRequest describes a VERIFY command (SP 800-73-5 Part 2, Sec. 3.2.1).
// Data is encoded reference data: an eight-byte PIN or pairing code, or on-card
// comparison (OCC) authentication data, as required by Reference.
// Empty Data queries the reference's security status without consuming a retry.
// ResetSecurityStatus selects P1=FF to clear that status; Data must then be empty.
// Data is borrowed for the call and must not be modified concurrently.
type VerifyRequest struct {
	Reference           KeyReference
	ResetSecurityStatus bool
	Data                []byte
}
