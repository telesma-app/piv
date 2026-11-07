package protocol

import (
	"errors"
	"fmt"

	"github.com/telesma-app/iso7816"
)

var ErrInvalidResponse = errors.New("piv: invalid response")

// Instruction is a PIV command instruction byte.
type Instruction byte

const (
	Select                    Instruction = 0xa4
	GetData                   Instruction = 0xcb
	PutData                   Instruction = 0xdb
	Verify                    Instruction = 0x20
	ChangeReferenceData       Instruction = 0x24
	ResetRetryCounter         Instruction = 0x2c
	GeneralAuthenticate       Instruction = 0x87
	GenerateAsymmetricKeyPair Instruction = 0x47
)

// SelectCommand selects the PIV application by its nine-byte AID prefix.
func SelectCommand() iso7816.Command {
	return iso7816.Command{
		INS: byte(Select), P1: 0x04,
		Data: []byte{0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00},
		Le:   256, Encoding: iso7816.EncodingShort,
	}
}

// KeyReference identifies a PIV key or authentication reference. The Card
// Application Administration key (9B) authorizes administrative commands; the
// Key Management key (9D) is the cardholder's asymmetric confidentiality key.
type KeyReference byte

const (
	GlobalPIN                     KeyReference = 0x00
	SecureMessaging               KeyReference = 0x04
	ApplicationPIN                KeyReference = 0x80
	PUK                           KeyReference = 0x81
	PrimaryFingerOCC              KeyReference = 0x96
	SecondaryFingerOCC            KeyReference = 0x97
	PairingCode                   KeyReference = 0x98
	PIVAuthentication             KeyReference = 0x9a
	CardApplicationAdministration KeyReference = 0x9b
	DigitalSignature              KeyReference = 0x9c
	KeyManagement                 KeyReference = 0x9d
	CardAuthentication            KeyReference = 0x9e
	RetiredKey1                   KeyReference = 0x82
	RetiredKey20                  KeyReference = 0x95
)

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

// Object identifies a PIV data object used with GET DATA and PUT DATA.
type Object uint32

const (
	CardCapabilityContainer                Object = 0x5fc107
	CardholderUniqueIdentifier             Object = 0x5fc102
	CardholderFingerprints                 Object = 0x5fc103
	CardholderFacialImage                  Object = 0x5fc108
	PIVAuthenticationCertificate           Object = 0x5fc105
	DigitalSignatureCertificate            Object = 0x5fc10a
	KeyManagementCertificate               Object = 0x5fc10b
	CardAuthenticationCertificate          Object = 0x5fc101
	SecurityObject                         Object = 0x5fc106
	PrintedInformation                     Object = 0x5fc109
	DiscoveryObject                        Object = 0x7e
	BiometricInformationTemplates          Object = 0x7f61
	KeyHistoryObject                       Object = 0x5fc10c
	RetiredCertificate1                    Object = 0x5fc10d
	RetiredCertificate20                   Object = 0x5fc120
	CardholderIrisImages                   Object = 0x5fc121
	SecureMessagingCertificateSignerObject Object = 0x5fc122
	PairingCodeReferenceDataContainer      Object = 0x5fc123
)

// CertificateObject returns the certificate object associated with a key slot.
func CertificateObject(key KeyReference) (Object, error) {
	switch key {
	case PIVAuthentication:
		return PIVAuthenticationCertificate, nil
	case DigitalSignature:
		return DigitalSignatureCertificate, nil
	case KeyManagement:
		return KeyManagementCertificate, nil
	case CardAuthentication:
		return CardAuthenticationCertificate, nil
	default:
		if key >= RetiredKey1 && key <= RetiredKey20 {
			return RetiredCertificate1 + Object(key-RetiredKey1), nil
		}

		return 0, fmt.Errorf("piv: key reference %02x has no certificate object", byte(key))
	}
}
