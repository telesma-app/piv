package protocol

import (
	"fmt"

	"github.com/telesma-app/piv/internal/bertlv"
)

// DynamicAuthentication is the content of a GENERAL AUTHENTICATE template.
// A nil field is absent; a non-nil empty field requests that authentication step.
type DynamicAuthentication struct {
	Witness        []byte
	Challenge      []byte
	Response       []byte
	Exponentiation []byte
}

// MarshalBinary encodes a dynamic authentication template (tag 0x7c).
func (a DynamicAuthentication) MarshalBinary() ([]byte, error) {
	var data []byte
	if a.Witness != nil {
		data = bertlv.Append(data, 0x80, a.Witness)
		if a.Challenge != nil {
			data = bertlv.Append(data, 0x81, a.Challenge)
		}
	}

	if a.Response != nil {
		data = bertlv.Append(data, 0x82, a.Response)
	}
	// Mutual authentication uses 80, 81, 82 (Part 2, Table 23); private-key
	// operations request 82 before supplying their 81 input (Appendix A.4).
	if a.Witness == nil && a.Challenge != nil {
		data = bertlv.Append(data, 0x81, a.Challenge)
	}

	if a.Exponentiation != nil {
		data = bertlv.Append(data, 0x85, a.Exponentiation)
	}

	return bertlv.Append(nil, 0x7c, data), nil
}

// ParseDynamicAuthentication parses one dynamic authentication template.
// Fields borrow data. Unknown fields are ignored.
func ParseDynamicAuthentication(data []byte) (DynamicAuthentication, error) {
	data, err := ParseObject(data, 0x7c)
	if err != nil {
		return DynamicAuthentication{}, err
	}

	var authentication DynamicAuthentication

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return DynamicAuthentication{}, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}

		data = rest

		var field *[]byte

		switch tag {
		case 0x80:
			field = &authentication.Witness
		case 0x81:
			field = &authentication.Challenge
		case 0x82:
			field = &authentication.Response
		case 0x85:
			field = &authentication.Exponentiation
		default:
			continue
		}

		if *field != nil {
			return DynamicAuthentication{}, fmt.Errorf("%w: duplicate authentication tag %x", ErrInvalidResponse, tag)
		}

		*field = value
	}

	return authentication, nil
}
