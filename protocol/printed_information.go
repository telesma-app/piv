package protocol

import (
	"fmt"
	"time"

	"github.com/telesma-app/bertlv"
)

// PrintedInfo contains the optional Printed Information object's cardholder
// text (SP 800-73-5 Part 1, Sec. 3.3.1 and Table 15).
// Text is preserved as ASCII without trimming or normalization.
// ExpirationDate is midnight UTC on the printed date.
// Organization affiliation pointers distinguish absent and present-empty lines.
type PrintedInfo struct {
	Name                         string
	EmployeeAffiliation          string
	ExpirationDate               time.Time
	AgencyCardSerialNumber       string
	IssuerIdentification         string
	OrganizationAffiliationLine1 *string
	OrganizationAffiliationLine2 *string
}

// ParsePrintedInformation parses the object's content without its outer 53
// template, as returned by GetData. Name, employee affiliation, expiration date,
// agency card serial number, and issuer identification must be present. The
// expiration date uses YYYYMMMDD with an uppercase English month abbreviation;
// issuer identification is exactly 15 ASCII bytes. Other text fields follow the
// byte limits in Table 15. Unknown fields, including the removed tag 03, are
// ignored. An optional error detection code must be empty when present.
func ParsePrintedInformation(data []byte) (PrintedInfo, error) {
	var (
		info PrintedInfo
		seen uint16
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return PrintedInfo{}, fmt.Errorf("%w: printed information: %v", ErrInvalidResponse, err)
		}

		data = rest

		var presence uint16

		switch tag {
		case 0x01, 0x02, 0x04, 0x05, 0x06, 0x07, 0x08:
			presence = 1 << tag
		case 0xfe:
			presence = 1
		default:
			continue
		}

		if seen&presence != 0 {
			return PrintedInfo{}, fmt.Errorf("%w: duplicate printed information tag %x", ErrInvalidResponse, tag)
		}

		seen |= presence

		var field *string

		maxBytes := 20

		switch tag {
		case 0x01:
			field, maxBytes = &info.Name, 125
		case 0x02:
			field = &info.EmployeeAffiliation
		case 0x04:
			if len(value) != 9 {
				return PrintedInfo{}, fmt.Errorf("%w: invalid printed expiration date length", ErrInvalidResponse)
			}

			// FIPS 201-3, Sec. 4.1.4.1, Zone 14F defines JAN through DEC.
			// time.Parse also accepts lowercase months, which this format does not.
			for _, b := range value[4:7] {
				if b < 'A' || b > 'Z' {
					return PrintedInfo{}, fmt.Errorf("%w: invalid printed expiration month", ErrInvalidResponse)
				}
			}

			info.ExpirationDate, err = time.Parse("2006Jan02", string(value))
			if err != nil {
				return PrintedInfo{}, fmt.Errorf("%w: invalid printed expiration date", ErrInvalidResponse)
			}

			continue
		case 0x05:
			field = &info.AgencyCardSerialNumber
		case 0x06:
			if len(value) != 15 {
				return PrintedInfo{}, fmt.Errorf("%w: invalid printed issuer identification length", ErrInvalidResponse)
			}

			field = &info.IssuerIdentification
		case 0x07:
			info.OrganizationAffiliationLine1 = new(string)
			field = info.OrganizationAffiliationLine1
		case 0x08:
			info.OrganizationAffiliationLine2 = new(string)
			field = info.OrganizationAffiliationLine2
		case 0xfe:
			if len(value) != 0 {
				return PrintedInfo{}, fmt.Errorf("%w: invalid printed error detection code", ErrInvalidResponse)
			}

			continue
		}

		if len(value) > maxBytes {
			return PrintedInfo{}, fmt.Errorf("%w: printed information tag %x exceeds %d bytes", ErrInvalidResponse, tag, maxBytes)
		}

		for _, b := range value {
			if b > 0x7f {
				return PrintedInfo{}, fmt.Errorf("%w: non-ASCII printed information tag %x", ErrInvalidResponse, tag)
			}
		}

		*field = string(value)
	}

	const required = 1<<0x01 | 1<<0x02 | 1<<0x04 | 1<<0x05 | 1<<0x06
	if seen&required != required {
		return PrintedInfo{}, fmt.Errorf("%w: incomplete printed information", ErrInvalidResponse)
	}

	return info, nil
}
