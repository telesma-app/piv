package protocol

import (
	"bytes"
	"crypto"
	"encoding/asn1"
	"errors"
	"testing"
)

func TestSecurityObjectWire(t *testing.T) {
	// BA consists of three-byte DG/container entries, not GET DATA tags.
	wire := []byte{0xba, 6, 1, 0xdb, 0, 2, 0x30, 1, 0xbb, 2, 0x30, 0, 0xfe, 0}

	object, err := ParseSecurityObject(wire)
	if err != nil {
		t.Fatal(err)
	}

	if len(object.Mapping) != 2 || object.Mapping[0] != (DataGroupMapping{DataGroup: 1, ContainerID: 0xdb00}) || object.Mapping[1] != (DataGroupMapping{DataGroup: 2, ContainerID: 0x3001}) {
		t.Fatalf("mapping = %+v", object.Mapping)
	}

	if got := EncodeSecurityObject(object); !bytes.Equal(got, wire) {
		t.Errorf("encoded = %x, want %x", got, wire)
	}

	object.SignedData[1] = 1

	if wire[11] != 1 {
		t.Error("signature does not borrow source bytes")
	}
}

func TestSecurityObjectMalformed(t *testing.T) {
	for _, wire := range [][]byte{
		{}, {0xba, 0, 0xbb, 1, 1}, {0xba, 2, 1, 2, 0xbb, 1, 1},
		{0xba, 3, 0, 0x30, 0, 0xbb, 1, 1},
		{0xba, 6, 1, 0x30, 0, 1, 0x30, 1, 0xbb, 1, 1},
		{0xba, 6, 1, 0x30, 0, 2, 0x30, 0, 0xbb, 1, 1},
		{0xba, 3, 1, 0x30, 0, 0xbb, 0},
		{0xba, 3, 1, 0x30, 0, 0xbb, 1, 1, 0xfe, 1, 0},
	} {
		if _, err := ParseSecurityObject(wire); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseSecurityObject(%x) = %v", wire, err)
		}
	}
}

func TestLDSSecurityObject(t *testing.T) {
	// Independently encode the ICAO ASN.1 profile without production structs.
	for _, version := range []int{0, 1} {
		algorithm := []byte{0x30, 0x0b, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, 1}
		group := func(n byte) []byte {
			b := append([]byte{0x30, 0x25, 2, 1, n, 4, 0x20}, bytes.Repeat([]byte{n}, 32)...)
			return b
		}
		groups := append([]byte{0x30, 0x4e}, group(1)...)
		groups = append(groups, group(2)...)
		content := append([]byte{2, 1, byte(version)}, algorithm...)

		content = append(content, groups...)
		if version == 1 {
			content = append(content, 0x30, 13, 0x13, 4, '0', '1', '0', '8', 0x13, 5, '0', '4', '0', '0', '0')
		}

		wire := append([]byte{0x30, byte(len(content))}, content...)

		object, err := ParseLDSSecurityObject(wire)
		if err != nil {
			t.Fatal(err)
		}

		if object.HashAlgorithm != crypto.SHA256 || len(object.Hashes) != 2 || object.Hashes[1].DataGroup != 2 || !bytes.Equal(object.Hashes[1].Digest, bytes.Repeat([]byte{2}, 32)) {
			t.Fatalf("LDS = %+v", object)
		}

		if (object.VersionInfo != nil) != (version == 1) {
			t.Fatal("version information presence differs")
		}

		encoded, err := EncodeLDSSecurityObject(object)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(encoded, wire) {
			t.Errorf("LDS encoded = %x, want %x", encoded, wire)
		}
	}
}

func TestLDSRejectsMalformedDigestLists(t *testing.T) {
	base := LDSSecurityObject{HashAlgorithm: crypto.SHA384, Hashes: []DataGroupHash{{DataGroup: 1, Digest: make([]byte, 48)}, {DataGroup: 2, Digest: make([]byte, 48)}}}
	for _, modify := range []func(*LDSSecurityObject){
		func(o *LDSSecurityObject) { o.Hashes = o.Hashes[:1] },
		func(o *LDSSecurityObject) { o.Hashes[0].DataGroup = 0 },
		func(o *LDSSecurityObject) { o.Hashes[1].DataGroup = 1 },
		func(o *LDSSecurityObject) { o.Hashes[0].Digest = make([]byte, 32) },
	} {
		object := base
		object.Hashes = append([]DataGroupHash(nil), base.Hashes...)
		modify(&object)

		wire, err := EncodeLDSSecurityObject(object)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseLDSSecurityObject(wire); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("malformed LDS accepted: %x (%v)", wire, err)
		}
	}

	wire, err := EncodeLDSSecurityObject(base)
	if err != nil {
		t.Fatal(err)
	}

	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(wire, &raw); err != nil {
		t.Fatal(err)
	}

	raw.FullBytes = nil
	raw.Bytes = append(raw.Bytes, 5, 0)

	wire, err = asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseLDSSecurityObject(wire); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("extra LDS field accepted: %v", err)
	}
}

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
