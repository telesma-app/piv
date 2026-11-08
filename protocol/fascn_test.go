package protocol

import (
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestFASCNStandardVector(t *testing.T) {
	// TIG SCEPACS v2.3, Sec. 6.3, Figures 8-10 publish both the complete
	// 200-bit record and its field values. The LRC character is 7.
	// https://www.idmanagement.gov/docs/pacs-tig-scepacs.pdf#page=32
	encoded := fascnHex(t, "d0439458210c2c19a0846d83685a1082108ce73984108ca3fc")
	want := FASCN{
		AgencyCode: "0032", SystemCode: "0001", CredentialNumber: "092446",
		CredentialSeries: "0", IndividualCredentialIssue: "1", PersonIdentifier: "1112223333",
		OrganizationalCategory: "1", OrganizationalIdentifier: "1223", PersonOrganizationAssociation: "2",
	}

	got, err := ParseFASCN(encoded)
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Errorf("ParseFASCN = %+v, want %+v", got, want)
	}

	actual, err := EncodeFASCN(want)
	if err != nil {
		t.Fatal(err)
	}

	if actual != [25]byte(encoded) {
		t.Errorf("EncodeFASCN = %x, want %x", actual, encoded)
	}
}

func TestFASCNGSAInterop(t *testing.T) {
	// This unchanged public GSA test credential is an independent oracle;
	// its provenance is recorded in testdata/gsa/README.md. Its LRC is A,
	// which is a valid four-bit check value even though data digits are decimal.
	data, err := os.ReadFile("../testdata/gsa/card46-chuid.bin")
	if err != nil {
		t.Fatal(err)
	}

	chuid, err := ParseCHUID(data)
	if err != nil {
		t.Fatal(err)
	}

	want := FASCN{
		AgencyCode: "4700", SystemCode: "0257", CredentialNumber: "000046",
		CredentialSeries: "1", IndividualCredentialIssue: "1", PersonIdentifier: "0257000046",
		OrganizationalCategory: "1", OrganizationalIdentifier: "9999", PersonOrganizationAssociation: "1",
	}

	got, err := ParseFASCN(chuid.FASCN[:])
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Errorf("ParseFASCN = %+v, want %+v", got, want)
	}

	encoded, err := EncodeFASCN(want)
	if err != nil {
		t.Fatal(err)
	}

	if encoded != chuid.FASCN {
		t.Errorf("EncodeFASCN = %x, want GSA %x", encoded, chuid.FASCN)
	}
}

func TestParseFASCNRejectsMalformedRecords(t *testing.T) {
	for _, tc := range []struct {
		name string
		hex  string
	}{
		// These changes to the standard vector retain odd character parity.
		// Structural changes also adjust LRC, isolating the syntax checks.
		{name: "start sentinel", hex: "58439458210c2c19a0846d83685a1082108ce73984108ca3ed"},
		{name: "end sentinel", hex: "d0439458210c2c19a0846d83685a1082108ce73984108ca1cd"},
		{name: "agency separator", hex: "d043941c210c2c19a0846d83685a1082108ce73984108ca3ed"},
		{name: "system separator", hex: "d0439458210c0e19a0846d83685a1082108ce73984108ca3ed"},
		{name: "number separator", hex: "d0439458210c2c19a08469c3685a1082108ce73984108ca3ed"},
		{name: "series separator", hex: "d0439458210c2c19a0846d82785a1082108ce73984108ca3ed"},
		{name: "issue separator", hex: "d0439458210c2c19a0846d83681e1082108ce73984108ca3ed"},
		{name: "nondecimal data", hex: "d2c39458210c2c19a0846d83685a1082108ce73984108ca3f6"},
		{name: "longitudinal parity", hex: "d0439458210c2c19a0846d83685a1082108ce73984108ca3ed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseFASCN(fascnHex(t, tc.hex)); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseFASCN = %v, want ErrInvalidResponse", err)
			}
		})
	}

	for _, length := range []int{0, 24, 26} {
		if _, err := ParseFASCN(make([]byte, length)); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseFASCN with %d bytes = %v, want ErrInvalidResponse", length, err)
		}
	}
}

func TestParseFASCNRejectsEverySingleBitError(t *testing.T) {
	encoded := [25]byte(fascnHex(t, "d0439458210c2c19a0846d83685a1082108ce73984108ca3fc"))
	for bit := range 200 {
		corrupted := encoded
		corrupted[bit/8] ^= 1 << (bit % 8)

		if _, err := ParseFASCN(corrupted[:]); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseFASCN with bit %d flipped = %v, want ErrInvalidResponse", bit, err)
		}
	}
}

func TestEncodeFASCNFieldEncoding(t *testing.T) {
	base := FASCN{
		AgencyCode: "0000", SystemCode: "0000", CredentialNumber: "000000",
		CredentialSeries: "0", IndividualCredentialIssue: "0", PersonIdentifier: "0000000000",
		OrganizationalCategory: "0", OrganizationalIdentifier: "0000", PersonOrganizationAssociation: "0",
	}
	// SP 800-73-5 Part 1, Sec. 3.1.2 permits the non-identifier fields to
	// contain all zeros. Fixed-width zero and nine values also exercise every
	// decimal position without applying organization assignment policy.
	for _, digit := range []string{"0", "9"} {
		want := base
		want.AgencyCode = strings.Repeat(digit, 4)
		want.SystemCode = strings.Repeat(digit, 4)
		want.CredentialNumber = strings.Repeat(digit, 6)
		want.CredentialSeries = digit
		want.IndividualCredentialIssue = digit
		want.PersonIdentifier = strings.Repeat(digit, 10)
		want.OrganizationalCategory = digit
		want.OrganizationalIdentifier = strings.Repeat(digit, 4)
		want.PersonOrganizationAssociation = digit

		encoded, err := EncodeFASCN(want)
		if err != nil {
			t.Fatal(err)
		}

		got, err := ParseFASCN(encoded[:])
		if err != nil || got != want {
			t.Errorf("FASC-N with %s digits = %+v, %v, want %+v", digit, got, err, want)
		}
	}

	for _, field := range []struct {
		name  string
		width int
		set   func(*FASCN, string)
	}{
		{name: "agency", width: 4, set: func(n *FASCN, v string) { n.AgencyCode = v }},
		{name: "system", width: 4, set: func(n *FASCN, v string) { n.SystemCode = v }},
		{name: "number", width: 6, set: func(n *FASCN, v string) { n.CredentialNumber = v }},
		{name: "series", width: 1, set: func(n *FASCN, v string) { n.CredentialSeries = v }},
		{name: "issue", width: 1, set: func(n *FASCN, v string) { n.IndividualCredentialIssue = v }},
		{name: "person", width: 10, set: func(n *FASCN, v string) { n.PersonIdentifier = v }},
		{name: "category", width: 1, set: func(n *FASCN, v string) { n.OrganizationalCategory = v }},
		{name: "organization", width: 4, set: func(n *FASCN, v string) { n.OrganizationalIdentifier = v }},
		{name: "association", width: 1, set: func(n *FASCN, v string) { n.PersonOrganizationAssociation = v }},
	} {
		t.Run(field.name, func(t *testing.T) {
			for _, value := range []string{"", strings.Repeat("0", field.width+1), strings.Repeat("0", field.width-1) + ":"} {
				number := base
				field.set(&number, value)

				if _, err := EncodeFASCN(number); err == nil {
					t.Errorf("EncodeFASCN accepted %s %q", field.name, value)
				}
			}
		})
	}
}

func fascnHex(t *testing.T, text string) []byte {
	t.Helper()

	data, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}

	return data
}
