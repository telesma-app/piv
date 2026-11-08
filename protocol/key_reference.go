package protocol

// KeyReference identifies a PIV key or authentication reference. The Card
// Application Administration key (9B) authorizes administrative commands; the
// Key Management key (9D) is the cardholder's asymmetric confidentiality key.
type KeyReference byte

const (
	// Authentication data references (Part 1, Table 4).
	GlobalPIN          KeyReference = 0x00
	ApplicationPIN     KeyReference = 0x80
	PUK                KeyReference = 0x81
	PrimaryFingerOCC   KeyReference = 0x96
	SecondaryFingerOCC KeyReference = 0x97
	PairingCode        KeyReference = 0x98

	// Cryptographic key references (Part 1, Table 5).
	SecureMessaging               KeyReference = 0x04
	PIVAuthentication             KeyReference = 0x9a
	CardApplicationAdministration KeyReference = 0x9b
	DigitalSignature              KeyReference = 0x9c
	KeyManagement                 KeyReference = 0x9d
	CardAuthentication            KeyReference = 0x9e
	RetiredKey1                   KeyReference = 0x82
	RetiredKey20                  KeyReference = 0x95
)
