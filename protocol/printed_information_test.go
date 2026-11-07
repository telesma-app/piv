package protocol

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"
)

func printedInformationFields() [][]byte {
	return [][]byte{
		{0x01, 11, ' ', 'D', 'O', 'E', ',', ' ', 'J', 'A', 'N', 'E', ' '},
		{0x02, 10, 'C', 'o', 'n', 't', 'r', 'a', 'c', 't', 'o', 'r'},
		{0x04, 9, '2', '0', '3', '0', 'F', 'E', 'B', '2', '8'},
		{0x05, 6, 'S', 'N', '-', '0', '0', '1'},
		{0x06, 15, 'I', 'S', 'S', 'U', 'E', 'R', '-', '0', '0', '0', '0', '0', '0', '0', '1'},
	}
}

func printedInformationField(tag byte, value []byte) []byte {
	return append([]byte{tag, byte(len(value))}, value...)
}

func TestParsePrintedInformation(t *testing.T) {
	data := slices.Concat(printedInformationFields()...)
	data = append(data, 0x07, 11, 'E', 'n', 'g', 'i', 'n', 'e', 'e', 'r', 'i', 'n', 'g', 0x08, 0, 0xfe, 0)

	got, err := ParsePrintedInformation(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.Name != " DOE, JANE " || got.EmployeeAffiliation != "Contractor" ||
		got.AgencyCardSerialNumber != "SN-001" || got.IssuerIdentification != "ISSUER-00000001" {
		t.Errorf("printed information = %+v", got)
	}

	if want := time.Date(2030, time.February, 28, 0, 0, 0, 0, time.UTC); got.ExpirationDate != want {
		t.Errorf("expiration date = %v, want %v", got.ExpirationDate, want)
	}

	if got.OrganizationAffiliationLine1 == nil || *got.OrganizationAffiliationLine1 != "Engineering" {
		t.Errorf("organization affiliation line 1 = %v", got.OrganizationAffiliationLine1)
	}

	if got.OrganizationAffiliationLine2 == nil || *got.OrganizationAffiliationLine2 != "" {
		t.Error("present-empty organization affiliation line 2 was lost")
	}

	data[2] = 'X'

	if got.Name != " DOE, JANE " {
		t.Error("modifying the object changed parsed text")
	}
}

func TestParsePrintedInformationOptionalFieldsAndUnknownTags(t *testing.T) {
	fields := printedInformationFields()
	slices.Reverse(fields)
	data := slices.Concat(fields...)
	// Tag 03 was removed from the printed-information data model. Neither it nor
	// a future unknown tag acquires text constraints from a different field.
	data = append(data, 0x03, 1, 0xff, 0x90, 1, 0xff, 0x90, 0)

	got, err := ParsePrintedInformation(data)
	if err != nil {
		t.Fatal(err)
	}

	if got.OrganizationAffiliationLine1 != nil || got.OrganizationAffiliationLine2 != nil {
		t.Fatal("missing organization affiliation lines became present")
	}

	data = append(data, 0x08, 0)

	got, err = ParsePrintedInformation(data)
	if err != nil || got.OrganizationAffiliationLine1 != nil || got.OrganizationAffiliationLine2 == nil || *got.OrganizationAffiliationLine2 != "" {
		t.Fatalf("line 2 without line 1 = %+v, %v", got, err)
	}
}

func TestParsePrintedInformationPermitsEmptyVariableText(t *testing.T) {
	fields := printedInformationFields()
	fields[0], fields[1], fields[3] = []byte{1, 0}, []byte{2, 0}, []byte{5, 0}
	data := slices.Concat(fields...)

	got, err := ParsePrintedInformation(data)
	if err != nil || got.Name != "" || got.EmployeeAffiliation != "" || got.AgencyCardSerialNumber != "" {
		t.Fatalf("present-empty variable text = %+v, %v", got, err)
	}
}

func TestParsePrintedInformationRequiresMandatoryFields(t *testing.T) {
	for omitted := range printedInformationFields() {
		fields := printedInformationFields()
		fields = slices.Delete(fields, omitted, omitted+1)

		if _, err := ParsePrintedInformation(slices.Concat(fields...)); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("missing mandatory field %d = %v, want ErrInvalidResponse", omitted, err)
		}
	}
}

func TestParsePrintedInformationRejectsDuplicateKnownFields(t *testing.T) {
	fields := append(printedInformationFields(), []byte{7, 0}, []byte{8, 0}, []byte{0xfe, 0})
	for _, duplicate := range fields {
		data := slices.Concat(fields...)
		data = append(data, duplicate...)

		if _, err := ParsePrintedInformation(data); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("duplicate tag %02x = %v, want ErrInvalidResponse", duplicate[0], err)
		}
	}
}

func TestParsePrintedInformationTextBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tag   byte
		index int
		limit int
	}{
		{name: "name", tag: 1, index: 0, limit: 125},
		{name: "employee affiliation", tag: 2, index: 1, limit: 20},
		{name: "serial number", tag: 5, index: 3, limit: 20},
		{name: "issuer", tag: 6, index: 4, limit: 15},
		{name: "organization line 1", tag: 7, index: 5, limit: 20},
		{name: "organization line 2", tag: 8, index: 5, limit: 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, excess := range []bool{false, true} {
				fields := append(printedInformationFields(), nil)

				size := tc.limit
				if excess {
					size++
				}

				fields[tc.index] = printedInformationField(tc.tag, bytes.Repeat([]byte{'A'}, size))

				_, err := ParsePrintedInformation(slices.Concat(fields...))
				if excess && !errors.Is(err, ErrInvalidResponse) {
					t.Errorf("%d-byte text = %v, want ErrInvalidResponse", size, err)
				} else if !excess && err != nil {
					t.Errorf("maximum-size text = %v", err)
				}
			}

			fields := append(printedInformationFields(), nil)
			value := bytes.Repeat([]byte{'A'}, tc.limit)
			value[len(value)-1] = 0x80
			fields[tc.index] = printedInformationField(tc.tag, value)

			if _, err := ParsePrintedInformation(slices.Concat(fields...)); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("non-ASCII text = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestParsePrintedInformationRejectsInvalidDates(t *testing.T) {
	for _, date := range []string{
		"", "20300228", "2030February28", "2030Feb28", "2030feb28", "2030ZZZ28",
		"2030JAN00", "2030JAN32", "2030APR31", "2023FEB29", "20x0JAN01", "2030JANx1",
	} {
		t.Run(date, func(t *testing.T) {
			fields := printedInformationFields()
			fields[2] = printedInformationField(4, []byte(date))

			if _, err := ParsePrintedInformation(slices.Concat(fields...)); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("expiration %q = %v, want ErrInvalidResponse", date, err)
			}
		})
	}

	fields := printedInformationFields()
	fields[2] = printedInformationField(4, []byte("2024FEB29"))

	got, err := ParsePrintedInformation(slices.Concat(fields...))
	if want := time.Date(2024, time.February, 29, 0, 0, 0, 0, time.UTC); err != nil || got.ExpirationDate != want {
		t.Fatalf("leap-day expiration = %v, %v; want %v", got.ExpirationDate, err, want)
	}
}

func TestParsePrintedInformationRejectsMalformedObjects(t *testing.T) {
	valid := slices.Concat(printedInformationFields()...)
	shortIssuer := printedInformationFields()
	shortIssuer[4] = printedInformationField(6, bytes.Repeat([]byte{'A'}, 14))

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "unknown fields only", data: []byte{0x90, 0}},
		{name: "short issuer", data: slices.Concat(shortIssuer...)},
		{name: "truncated field", data: append(slices.Clone(valid), 0x90, 1)},
		{name: "nonempty error detection code", data: append(slices.Clone(valid), 0xfe, 1, 0)},
		{name: "outer template", data: append([]byte{0x53, byte(len(valid))}, valid...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePrintedInformation(tc.data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("ParsePrintedInformation = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
