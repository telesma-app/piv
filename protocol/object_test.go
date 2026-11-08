package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestContainerIDForObject(t *testing.T) {
	for _, tc := range []struct {
		object Object
		want   ContainerID
	}{
		{CardCapabilityContainer, 0xdb00}, {CardholderUniqueIdentifier, 0x3000}, {PIVAuthenticationCertificate, 0x0101}, {CardholderFingerprints, 0x6010},
		{SecurityObject, 0x9000}, {CardholderFacialImage, 0x6030}, {CardAuthenticationCertificate, 0x0500}, {DigitalSignatureCertificate, 0x0100},
		{KeyManagementCertificate, 0x0102}, {PrintedInformation, 0x3001}, {DiscoveryObject, 0x6050}, {KeyHistoryObject, 0x6060},
		{RetiredCertificate1, 0x1001}, {RetiredCertificate1 + 9, 0x100a}, {RetiredCertificate20, 0x1014},
		{CardholderIrisImages, 0x1015}, {BiometricInformationTemplates, 0x1016}, {SecureMessagingCertificateSignerObject, 0x1017}, {PairingCodeReferenceDataContainer, 0x1018},
	} {
		got, err := ContainerIDForObject(tc.object)
		if err != nil || got != tc.want {
			t.Errorf("container(%x) = %04x, %v, want %04x", tc.object, got, err, tc.want)
		}

		object, err := ObjectForContainerID(tc.want)
		if err != nil || object != tc.object {
			t.Errorf("object(%04x) = %x, %v, want %x", tc.want, object, err, tc.object)
		}
	}
}

func TestParseObject(t *testing.T) {
	value, err := ParseObject([]byte{0x53, 1, 0x42}, 0x53)
	if err != nil || !bytes.Equal(value, []byte{0x42}) {
		t.Fatalf("ParseObject = (%x, %v)", value, err)
	}

	for _, raw := range [][]byte{{0x70, 0}, {0x53, 0, 0xfe, 0}, {0x53, 1}} {
		if _, err := ParseObject(raw, 0x53); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseObject(%x) error = %v, want ErrInvalidResponse", raw, err)
		}
	}
}
