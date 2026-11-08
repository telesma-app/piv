package protocol

import (
	"errors"
	"fmt"

	"github.com/telesma-app/bertlv"
)

// EncodePairingCode encodes the Pairing Code Reference Data Container without
// its outer 53 template, for PutData (SP 800-73-5 Part 1, Sec. 3.3.8 and
// Table 44). Code must contain exactly eight ASCII decimal digits.
func EncodePairingCode(code string) ([]byte, error) {
	if len(code) != 8 {
		return nil, errors.New("piv: pairing code must contain eight ASCII digits")
	}

	for i := range code {
		if code[i] < '0' || code[i] > '9' {
			return nil, errors.New("piv: pairing code must contain eight ASCII digits")
		}
	}

	data := bertlv.Append(nil, 0x99, []byte(code))

	return append(data, 0xfe, 0), nil
}

// ParsePairingCode parses the Pairing Code Reference Data Container without
// its outer 53 template, as returned by GetData. The code must contain exactly
// eight ASCII decimal digits. Unknown fields are ignored; an error detection
// code, if present, must be empty.
func ParsePairingCode(data []byte) (string, error) {
	var (
		code              string
		haveCode, haveEDC bool
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return "", fmt.Errorf("%w: pairing code: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x99:
			if haveCode || len(value) != 8 {
				return "", fmt.Errorf("%w: invalid pairing code", ErrInvalidResponse)
			}

			for _, digit := range value {
				if digit < '0' || digit > '9' {
					return "", fmt.Errorf("%w: invalid pairing code", ErrInvalidResponse)
				}
			}

			code, haveCode = string(value), true
		case 0xfe:
			if haveEDC || len(value) != 0 {
				return "", fmt.Errorf("%w: invalid pairing code error detection code", ErrInvalidResponse)
			}

			haveEDC = true
		}
	}

	if !haveCode {
		return "", fmt.Errorf("%w: missing pairing code", ErrInvalidResponse)
	}

	return code, nil
}
