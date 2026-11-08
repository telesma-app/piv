package protocol

import (
	"fmt"
	"math/bits"
)

// FASCN is the Federal Agency Smart Credential Number defined by TIG SCEPACS
// v2.3, Secs. 6.1-6.3, as profiled by SP 800-73-5 Part 1, Sec. 3.1.2.
// Fields contain fixed-width ASCII decimal digits, including leading zeros.
// Agency and organization code assignments are not evaluated.
type FASCN struct {
	AgencyCode                    string // Four digits.
	SystemCode                    string // Four digits.
	CredentialNumber              string // Six digits.
	CredentialSeries              string // One digit.
	IndividualCredentialIssue     string // One digit.
	PersonIdentifier              string // Ten digits.
	OrganizationalCategory        string // One digit.
	OrganizationalIdentifier      string // Four digits.
	PersonOrganizationAssociation string // One digit.
}

// EncodeFASCN encodes the 25-byte FASC-N value used in CHUID.FASCN. Each field
// must contain its specified number of ASCII decimal digits. Sentinels, field
// separators, odd character parity, and the longitudinal check are generated.
func EncodeFASCN(number FASCN) ([25]byte, error) {
	characters := [40]byte{0: 0x0b, 5: 0x0d, 10: 0x0d, 17: 0x0d, 19: 0x0d, 21: 0x0d, 38: 0x0f}

	for _, field := range [...]struct {
		name       string
		value      string
		start, end int
	}{
		{name: "agency code", value: number.AgencyCode, start: 1, end: 5},
		{name: "system code", value: number.SystemCode, start: 6, end: 10},
		{name: "credential number", value: number.CredentialNumber, start: 11, end: 17},
		{name: "credential series", value: number.CredentialSeries, start: 18, end: 19},
		{name: "individual credential issue", value: number.IndividualCredentialIssue, start: 20, end: 21},
		{name: "person identifier", value: number.PersonIdentifier, start: 22, end: 32},
		{name: "organizational category", value: number.OrganizationalCategory, start: 32, end: 33},
		{name: "organizational identifier", value: number.OrganizationalIdentifier, start: 33, end: 37},
		{name: "person/organization association", value: number.PersonOrganizationAssociation, start: 37, end: 38},
	} {
		if len(field.value) != field.end-field.start {
			return [25]byte{}, fmt.Errorf("piv: FASC-N %s must contain %d ASCII digits", field.name, field.end-field.start)
		}

		for i := range field.value {
			digit := field.value[i]
			if digit < '0' || digit > '9' {
				return [25]byte{}, fmt.Errorf("piv: FASC-N %s must contain ASCII digits", field.name)
			}

			characters[field.start+i] = digit - '0'
		}
	}

	// The LRC gives even longitudinal parity across the four data bits;
	// its own fifth bit gives odd character parity like every other character.
	for _, character := range characters[:39] {
		characters[39] ^= character
	}

	var encoded [25]byte

	for i, character := range characters {
		if bits.OnesCount8(character)%2 == 0 {
			character |= 0x10
		}

		// Data bits are emitted least significant first, then the parity bit.
		// The first transmitted bit occupies the first byte's most significant bit.
		for bit := range 5 {
			offset := 5*i + bit
			encoded[offset/8] |= ((character >> bit) & 1) << (7 - offset%8)
		}
	}

	return encoded, nil
}

// ParseFASCN decodes a 25-byte FASC-N value, such as CHUID.FASCN[:]. It checks
// digit encoding, sentinels, separators, odd character parity, and the LRC.
// Parsing does not authenticate the credential or establish identifier trust.
func ParseFASCN(data []byte) (FASCN, error) {
	if len(data) != 25 {
		return FASCN{}, fmt.Errorf("%w: FASC-N must contain 25 bytes", ErrInvalidResponse)
	}

	var (
		characters [40]byte
		lrc        byte
	)

	for i := range characters {
		var character byte

		for bit := range 5 {
			offset := 5*i + bit
			character |= ((data[offset/8] >> (7 - offset%8)) & 1) << bit
		}

		if bits.OnesCount8(character)%2 != 1 {
			return FASCN{}, fmt.Errorf("%w: FASC-N character %d parity", ErrInvalidResponse, i)
		}

		characters[i] = character & 0x0f
		lrc ^= characters[i]
	}

	if lrc != 0 {
		return FASCN{}, fmt.Errorf("%w: FASC-N longitudinal check", ErrInvalidResponse)
	}

	if characters[0] != 0x0b || characters[38] != 0x0f {
		return FASCN{}, fmt.Errorf("%w: FASC-N sentinel", ErrInvalidResponse)
	}

	for i := 1; i < 38; i++ {
		switch i {
		case 5, 10, 17, 19, 21:
			if characters[i] != 0x0d {
				return FASCN{}, fmt.Errorf("%w: FASC-N field separator", ErrInvalidResponse)
			}
		default:
			if characters[i] > 9 {
				return FASCN{}, fmt.Errorf("%w: FASC-N nondecimal digit", ErrInvalidResponse)
			}

			characters[i] += '0'
		}
	}

	return FASCN{
		AgencyCode:                    string(characters[1:5]),
		SystemCode:                    string(characters[6:10]),
		CredentialNumber:              string(characters[11:17]),
		CredentialSeries:              string(characters[18:19]),
		IndividualCredentialIssue:     string(characters[20:21]),
		PersonIdentifier:              string(characters[22:32]),
		OrganizationalCategory:        string(characters[32:33]),
		OrganizationalIdentifier:      string(characters[33:37]),
		PersonOrganizationAssociation: string(characters[37:38]),
	}, nil
}
