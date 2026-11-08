package protocol

import (
	"fmt"

	"github.com/telesma-app/bertlv"
)

// CCC contains the Card Capability Container (SP 800-73-5 Part 1, Sec. 3.1.1 and
// Table 9). DataModel is the registered data model number; PIV uses 10 hex, and
// unknown values are preserved. Other fields describe GSC-IS compatibility,
// not the supported cryptographic algorithms of a PIV card.
//
// All slices and pointers borrow the parsed input. Nil scalar pointers mean
// unspecified values, whether their fields were absent or encoded with zero
// length. Raw preserves that distinction and the complete original encoding.
// ApplicationsCardURL is the opaque GSC-IS field, not a decoded textual URL.
type CCC struct {
	Raw                        []byte
	CardIdentifier             *[21]byte
	CapabilityContainerVersion *byte
	CapabilityGrammarVersion   *byte
	ApplicationsCardURL        []byte
	PKCS15                     *byte
	DataModel                  byte
	AccessControlRuleTable     []byte
}

// EncodeCCC encodes a CCC's known fields without the outer 53 template,
// for PutData (SP 800-73-5 Part 1, Table 9). Raw is ignored. Unspecified
// mandatory fields are encoded with zero length. The caller supplies field
// contents according to CCC's length contracts.
func EncodeCCC(ccc CCC) []byte {
	var cardIdentifier []byte
	if ccc.CardIdentifier != nil {
		cardIdentifier = ccc.CardIdentifier[:]
	}

	data := bertlv.Append(nil, 0xf0, cardIdentifier)
	if ccc.CapabilityContainerVersion == nil {
		data = append(data, 0xf1, 0)
	} else {
		data = append(data, 0xf1, 1, *ccc.CapabilityContainerVersion)
	}

	if ccc.CapabilityGrammarVersion == nil {
		data = append(data, 0xf2, 0)
	} else {
		data = append(data, 0xf2, 1, *ccc.CapabilityGrammarVersion)
	}

	data = bertlv.Append(data, 0xf3, ccc.ApplicationsCardURL)
	if ccc.PKCS15 == nil {
		data = append(data, 0xf4, 0)
	} else {
		data = append(data, 0xf4, 1, *ccc.PKCS15)
	}

	data = append(data, 0xf5, 1, ccc.DataModel)
	data = bertlv.Append(data, 0xf6, ccc.AccessControlRuleTable)

	return append(data, 0xf7, 0, 0xfa, 0, 0xfb, 0, 0xfc, 0, 0xfd, 0, 0xfe, 0)
}

// ParseCCC parses object contents without the outer 53 template, as returned
// by GetData. The one-byte data model number is required. Section 3.1.1 permits
// other mandatory fields to be empty; this parser also accepts their absence
// in sparse token objects. Known fields are checked for their encoded lengths
// and may appear only once; unknown and removed legacy fields are ignored.
func ParseCCC(data []byte) (CCC, error) {
	ccc := CCC{Raw: data}

	var seen [15]bool

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return CCC{}, fmt.Errorf("%w: CCC: %v", ErrInvalidResponse, err)
		}

		data = rest

		// Table 9 leaves F8 and F9 unassigned.
		if tag < 0xf0 || tag > 0xfe || tag == 0xf8 || tag == 0xf9 {
			continue
		}

		if seen[tag-0xf0] {
			return CCC{}, fmt.Errorf("%w: duplicate CCC field %x", ErrInvalidResponse, tag)
		}

		seen[tag-0xf0] = true

		switch tag {
		case 0xf0:
			if len(value) != 0 && len(value) != 21 {
				return CCC{}, fmt.Errorf("%w: invalid CCC card identifier", ErrInvalidResponse)
			}

			if len(value) != 0 {
				ccc.CardIdentifier = (*[21]byte)(value)
			}
		case 0xf1, 0xf2, 0xf4:
			if len(value) > 1 {
				return CCC{}, fmt.Errorf("%w: invalid CCC field %x length", ErrInvalidResponse, tag)
			}

			if len(value) == 0 {
				continue
			}

			switch tag {
			case 0xf1:
				ccc.CapabilityContainerVersion = &value[0]
			case 0xf2:
				ccc.CapabilityGrammarVersion = &value[0]
			case 0xf4:
				ccc.PKCS15 = &value[0]
			}
		case 0xf3:
			if len(value) > 128 {
				return CCC{}, fmt.Errorf("%w: invalid CCC applications CardURL length", ErrInvalidResponse)
			}

			ccc.ApplicationsCardURL = value
		case 0xf5:
			if len(value) != 1 {
				return CCC{}, fmt.Errorf("%w: invalid CCC data model number", ErrInvalidResponse)
			}

			ccc.DataModel = value[0]
		case 0xf6:
			if len(value) != 0 && len(value) != 17 {
				return CCC{}, fmt.Errorf("%w: invalid CCC access control rule table", ErrInvalidResponse)
			}

			ccc.AccessControlRuleTable = value
		case 0xf7, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe:
			if len(value) != 0 {
				return CCC{}, fmt.Errorf("%w: nonempty CCC field %x", ErrInvalidResponse, tag)
			}
		}
	}

	if !seen[5] {
		return CCC{}, fmt.Errorf("%w: missing CCC data model number", ErrInvalidResponse)
	}

	return ccc, nil
}
