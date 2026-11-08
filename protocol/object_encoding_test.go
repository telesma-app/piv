package protocol

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestEncodeCHUID(t *testing.T) {
	chuid := CHUID{
		FASCN: [25]byte{1, 2}, GUID: [16]byte{3, 4},
		ExpirationDate: time.Date(2030, time.February, 28, 0, 0, 0, 0, time.UTC),
		CardholderUUID: &[16]byte{5, 6}, IssuerSignature: []byte{0x30, 0},
	}
	want := []byte{
		0x30, 25, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x34, 16, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x35, 8, '2', '0', '3', '0', '0', '2', '2', '8',
		0x36, 16, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x3e, 2, 0x30, 0, 0xfe, 0,
	}

	got := EncodeCHUID(chuid)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeCHUID = %x, want %x", got, want)
	}

	parsed, err := ParseCHUID(got)
	if err != nil {
		t.Fatal(err)
	}

	parsed.Raw = nil
	if !reflect.DeepEqual(parsed, chuid) {
		t.Errorf("CHUID = %+v, want %+v", parsed, chuid)
	}
}

func TestEncodeCHUIDOptionalFields(t *testing.T) {
	chuid := CHUID{ExpirationDate: time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)}
	for _, signature := range [][]byte{nil, {}} {
		chuid.IssuerSignature = signature

		data := EncodeCHUID(chuid)

		got, err := ParseCHUID(data)
		if err != nil {
			t.Fatal(err)
		}

		if got.CardholderUUID != nil || (got.IssuerSignature == nil) != (signature == nil) {
			t.Errorf("optional fields = %+v, signature input %v", got, signature)
		}

		wantSuffix := []byte{0xfe, 0}
		if signature != nil {
			wantSuffix = []byte{0x3e, 0, 0xfe, 0}
		}

		if !bytes.HasSuffix(data, wantSuffix) {
			t.Errorf("CHUID suffix = %x, want %x", data, wantSuffix)
		}
	}
}

func TestEncodeCCC(t *testing.T) {
	containerVersion, grammarVersion, pkcs15 := byte(0x21), byte(0x22), byte(0)
	ccc := CCC{
		CardIdentifier: &[21]byte{1, 2}, CapabilityContainerVersion: &containerVersion,
		CapabilityGrammarVersion: &grammarVersion, ApplicationsCardURL: []byte{0xa0, 1},
		PKCS15: &pkcs15, DataModel: 0x10, AccessControlRuleTable: make([]byte, 17),
	}
	want := []byte{
		0xf0, 21, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0xf1, 1, 0x21, 0xf2, 1, 0x22, 0xf3, 2, 0xa0, 1, 0xf4, 1, 0, 0xf5, 1, 0x10,
		0xf6, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0xf7, 0, 0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0,
	}

	got := EncodeCCC(ccc)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeCCC = %x, want %x", got, want)
	}

	parsed, err := ParseCCC(got)
	if err != nil {
		t.Fatal(err)
	}

	parsed.Raw = nil
	if !reflect.DeepEqual(parsed, ccc) {
		t.Errorf("CCC = %+v, want %+v", parsed, ccc)
	}
}

func TestEncodeCCCEmptyMandatoryFields(t *testing.T) {
	want := []byte{
		0xf0, 0, 0xf1, 0, 0xf2, 0, 0xf3, 0, 0xf4, 0, 0xf5, 1, 0x10,
		0xf6, 0, 0xf7, 0, 0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0,
	}

	got := EncodeCCC(CCC{DataModel: 0x10})
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeCCC = %x, want %x", got, want)
	}

	if _, err := ParseCCC(got); err != nil {
		t.Fatal(err)
	}
}

func TestEncodePrintedInformation(t *testing.T) {
	line1, line2 := "Engineering", ""
	info := PrintedInfo{
		Name: " DOE, JANE ", EmployeeAffiliation: "Contractor",
		ExpirationDate:         time.Date(2030, time.February, 28, 0, 0, 0, 0, time.UTC),
		AgencyCardSerialNumber: "SN-001", IssuerIdentification: "ISSUER-00000001",
		OrganizationAffiliationLine1: &line1, OrganizationAffiliationLine2: &line2,
	}
	want := []byte{
		0x01, 11, ' ', 'D', 'O', 'E', ',', ' ', 'J', 'A', 'N', 'E', ' ',
		0x02, 10, 'C', 'o', 'n', 't', 'r', 'a', 'c', 't', 'o', 'r',
		0x04, 9, '2', '0', '3', '0', 'F', 'E', 'B', '2', '8',
		0x05, 6, 'S', 'N', '-', '0', '0', '1',
		0x06, 15, 'I', 'S', 'S', 'U', 'E', 'R', '-', '0', '0', '0', '0', '0', '0', '0', '1',
		0x07, 11, 'E', 'n', 'g', 'i', 'n', 'e', 'e', 'r', 'i', 'n', 'g',
		0x08, 0, 0xfe, 0,
	}

	got := EncodePrintedInformation(info)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodePrintedInformation = %x, want %x", got, want)
	}

	parsed, err := ParsePrintedInformation(got)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(parsed, info) {
		t.Errorf("printed information = %+v, want %+v", parsed, info)
	}
}

func TestEncodePrintedInformationAbsentAffiliations(t *testing.T) {
	info := PrintedInfo{
		ExpirationDate:       time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC),
		IssuerIdentification: "ISSUER-00000001",
	}
	want := []byte{
		0x01, 0, 0x02, 0, 0x04, 9, '2', '0', '3', '0', 'J', 'A', 'N', '0', '1', 0x05, 0,
		0x06, 15, 'I', 'S', 'S', 'U', 'E', 'R', '-', '0', '0', '0', '0', '0', '0', '0', '1', 0xfe, 0,
	}

	got := EncodePrintedInformation(info)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodePrintedInformation = %x, want %x", got, want)
	}

	parsed, err := ParsePrintedInformation(got)
	if err != nil || !reflect.DeepEqual(parsed, info) {
		t.Errorf("printed information = %+v, %v, want %+v", parsed, err, info)
	}
}

func TestEncodeSecureMessagingCertificateSigner(t *testing.T) {
	for _, intermediate := range [][]byte{nil, {0x7f, 0x21, 0x81, 3, 1, 2, 3}} {
		signer := SecureMessagingCertificateSigner{CertificateDER: []byte{0x30, 0}, IntermediateCVC: intermediate}
		want := []byte{0x70, 2, 0x30, 0, 0x71, 1, 0}
		want = append(want, intermediate...)
		want = append(want, 0xfe, 0)

		got := EncodeSecureMessagingCertificateSigner(signer)
		if !bytes.Equal(got, want) {
			t.Errorf("EncodeSecureMessagingCertificateSigner = %x, want %x", got, want)
		}

		parsed, err := ParseSecureMessagingCertificateSigner(got)
		if err != nil || !reflect.DeepEqual(parsed, signer) {
			t.Errorf("signer = %+v, %v, want %+v", parsed, err, signer)
		}
	}
}

func TestEncodeOffCardKeyHistoryFile(t *testing.T) {
	certificates := []OffCardCertificate{
		{Key: RetiredKey20, DER: []byte{0x30, 3, 2, 1, 1}},
		{Key: RetiredKey1, DER: []byte{0x30, 0}},
	}
	want := []byte{
		0x30, 17,
		0x30, 8, 4, 1, 0x95, 0x30, 3, 2, 1, 1,
		0x30, 5, 4, 1, 0x82, 0x30, 0,
	}

	got := EncodeOffCardKeyHistoryFile(certificates)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeOffCardKeyHistoryFile = %x, want %x", got, want)
	}

	parsed, err := ParseOffCardKeyHistoryFile(got)
	if err != nil || !reflect.DeepEqual(parsed, certificates) {
		t.Errorf("certificates = %+v, %v, want %+v", parsed, err, certificates)
	}
}

func TestEncodeOffCardKeyHistoryFileLongDER(t *testing.T) {
	der := certificateDER(t)
	certificates := []OffCardCertificate{{Key: RetiredKey1, DER: der}}

	data := EncodeOffCardKeyHistoryFile(certificates)

	got, err := ParseOffCardKeyHistoryFile(data)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, certificates) {
		t.Errorf("certificates = %+v, want %+v", got, certificates)
	}
}
