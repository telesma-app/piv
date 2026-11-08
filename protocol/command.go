package protocol

// Instruction is a PIV command instruction byte (SP 800-73-5 Part 2, Sec. 3).
type Instruction byte

const (
	// Data access (Part 2, Sec. 3.1).
	Select  Instruction = 0xa4
	GetData Instruction = 0xcb

	// Authentication (Part 2, Sec. 3.2).
	Verify              Instruction = 0x20
	ChangeReferenceData Instruction = 0x24
	ResetRetryCounter   Instruction = 0x2c
	GeneralAuthenticate Instruction = 0x87

	// Administration (Part 2, Sec. 3.3).
	PutData                   Instruction = 0xdb
	GenerateAsymmetricKeyPair Instruction = 0x47
)
