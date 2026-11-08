package protocol

import (
	"fmt"

	"github.com/telesma-app/bertlv"
)

// Object identifies a PIV data object used with GET DATA and PUT DATA.
type Object uint32

const (
	// Mandatory data elements (Part 1, Sec. 3.1).
	CardCapabilityContainer       Object = 0x5fc107
	CardholderUniqueIdentifier    Object = 0x5fc102
	PIVAuthenticationCertificate  Object = 0x5fc105
	CardAuthenticationCertificate Object = 0x5fc101
	CardholderFingerprints        Object = 0x5fc103
	CardholderFacialImage         Object = 0x5fc108
	SecurityObject                Object = 0x5fc106

	// Conditional data elements (Part 1, Sec. 3.2).
	DigitalSignatureCertificate Object = 0x5fc10a
	KeyManagementCertificate    Object = 0x5fc10b

	// Optional data elements (Part 1, Sec. 3.3).
	PrintedInformation                     Object = 0x5fc109
	DiscoveryObject                        Object = 0x7e
	KeyHistoryObject                       Object = 0x5fc10c
	RetiredCertificate1                    Object = 0x5fc10d
	RetiredCertificate20                   Object = 0x5fc120
	CardholderIrisImages                   Object = 0x5fc121
	BiometricInformationTemplates          Object = 0x7f61
	SecureMessagingCertificateSignerObject Object = 0x5fc122
	PairingCodeReferenceDataContainer      Object = 0x5fc123
)

// ContainerID identifies a PIV data-model container, not a GET DATA tag
// (SP 800-73-5 Part 1, Table 2).
type ContainerID uint16

// ContainerIDForObject translates a GET DATA tag to its data-model container.
func ContainerIDForObject(object Object) (ContainerID, error) {
	switch object {
	case CardCapabilityContainer:
		return 0xdb00, nil
	case CardholderUniqueIdentifier:
		return 0x3000, nil
	case PIVAuthenticationCertificate:
		return 0x0101, nil
	case CardholderFingerprints:
		return 0x6010, nil
	case SecurityObject:
		return 0x9000, nil
	case CardholderFacialImage:
		return 0x6030, nil
	case CardAuthenticationCertificate:
		return 0x0500, nil
	case DigitalSignatureCertificate:
		return 0x0100, nil
	case KeyManagementCertificate:
		return 0x0102, nil
	case PrintedInformation:
		return 0x3001, nil
	case DiscoveryObject:
		return 0x6050, nil
	case KeyHistoryObject:
		return 0x6060, nil
	case CardholderIrisImages:
		return 0x1015, nil
	case BiometricInformationTemplates:
		return 0x1016, nil
	case SecureMessagingCertificateSignerObject:
		return 0x1017, nil
	case PairingCodeReferenceDataContainer:
		return 0x1018, nil
	default:
		if object >= RetiredCertificate1 && object <= RetiredCertificate20 {
			return 0x1001 + ContainerID(object-RetiredCertificate1), nil
		}

		return 0, fmt.Errorf("piv: object %x has no standard container ID", uint32(object))
	}
}

// ObjectForContainerID translates a data-model container to a GET DATA tag.
func ObjectForContainerID(container ContainerID) (Object, error) {
	switch container {
	case 0xdb00:
		return CardCapabilityContainer, nil
	case 0x3000:
		return CardholderUniqueIdentifier, nil
	case 0x0101:
		return PIVAuthenticationCertificate, nil
	case 0x6010:
		return CardholderFingerprints, nil
	case 0x9000:
		return SecurityObject, nil
	case 0x6030:
		return CardholderFacialImage, nil
	case 0x0500:
		return CardAuthenticationCertificate, nil
	case 0x0100:
		return DigitalSignatureCertificate, nil
	case 0x0102:
		return KeyManagementCertificate, nil
	case 0x3001:
		return PrintedInformation, nil
	case 0x6050:
		return DiscoveryObject, nil
	case 0x6060:
		return KeyHistoryObject, nil
	case 0x1015:
		return CardholderIrisImages, nil
	case 0x1016:
		return BiometricInformationTemplates, nil
	case 0x1017:
		return SecureMessagingCertificateSignerObject, nil
	case 0x1018:
		return PairingCodeReferenceDataContainer, nil
	default:
		if container >= 0x1001 && container <= 0x1014 {
			return RetiredCertificate1 + Object(container-0x1001), nil
		}

		return 0, fmt.Errorf("piv: container %04x has no standard object tag", uint16(container))
	}
}

// ParseObject reads an exact single object with the expected tag.
func ParseObject(data []byte, tag uint32) ([]byte, error) {
	got, value, rest, err := bertlv.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if got != tag || len(rest) != 0 {
		return nil, fmt.Errorf("%w: expected single tag %x, got %x", ErrInvalidResponse, tag, got)
	}

	return value, nil
}
