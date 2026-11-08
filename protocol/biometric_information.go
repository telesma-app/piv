package protocol

import (
	"encoding/binary"
	"fmt"

	"github.com/telesma-app/bertlv"
)

// BiometricSubtype identifies an OCC finger in ISO/IEC 19785-3:2007 encoding.
// These values differ from INCITS 378 finger positions (SP 800-76-2, Table 8).
type BiometricSubtype byte

const (
	BiometricFingerUnspecified BiometricSubtype = 0x00
	BiometricRightThumb        BiometricSubtype = 0x05
	BiometricRightIndex        BiometricSubtype = 0x09
	BiometricRightMiddle       BiometricSubtype = 0x0d
	BiometricRightRing         BiometricSubtype = 0x11
	BiometricRightLittle       BiometricSubtype = 0x15
	BiometricLeftThumb         BiometricSubtype = 0x06
	BiometricLeftIndex         BiometricSubtype = 0x0a
	BiometricLeftMiddle        BiometricSubtype = 0x0e
	BiometricLeftRing          BiometricSubtype = 0x12
	BiometricLeftLittle        BiometricSubtype = 0x16
)

// BiometricInformation describes the card's OCC configuration. An empty
// Templates slice describes a present BIT group with no enrolled OCC fingers.
// Raw borrows the complete parsed contents without the outer 7F61 template.
type BiometricInformation struct {
	Raw       []byte
	Templates []BiometricInformationTemplate
}

// BiometricInformationTemplate is the PIV BIT profile from SP 800-76-2,
// Table 7. MinutiaeOrder is the ISO/IEC 19794-2 order code, retained without
// interpretation. It tells the producer how to select/order the OCC minutiae.
// Raw borrows the contents of this finger's 7F60 template.
type BiometricInformationTemplate struct {
	Raw             []byte
	Reference       KeyReference
	Finger          BiometricSubtype
	FormatOwner     uint16
	FormatType      uint16
	MinutiaeMinimum byte
	MinutiaeMaximum byte
	MinutiaeOrder   byte
}

// EncodeBiometricInformation encodes the known PIV BIT fields without the
// outer 7F61 template for PutData. The caller supplies at most two templates
// in primary/secondary reference order and their card comparison parameters.
func EncodeBiometricInformation(information BiometricInformation) []byte {
	data := bertlv.Append(nil, 0x02, []byte{byte(len(information.Templates))})
	for _, template := range information.Templates {
		header := bertlv.Append(nil, 0x81, []byte{0x08})
		header = bertlv.Append(header, 0x82, []byte{byte(template.Finger)})
		header = bertlv.Append(header, 0x87, []byte{byte(template.FormatOwner >> 8), byte(template.FormatOwner)})
		header = bertlv.Append(header, 0x88, []byte{byte(template.FormatType >> 8), byte(template.FormatType)})
		parameters := bertlv.Append(nil, 0x81, []byte{template.MinutiaeMinimum, template.MinutiaeMaximum})
		parameters = bertlv.Append(parameters, 0x82, []byte{template.MinutiaeOrder})
		header = bertlv.Append(header, 0xb1, parameters)
		value := bertlv.Append(nil, 0x83, []byte{byte(template.Reference)})
		value = bertlv.Append(value, 0xa1, header)
		data = bertlv.Append(data, 0x7f60, value)
	}

	return data
}

// ParseBiometricInformation parses BIT group contents without the outer 7F61
// template, as returned by GetData. A PIV group contains zero, one, or two
// fingers (SP 800-73-5 Part 1, Sec. 3.3.6 and Table 42). The PIV profile uses
// fingerprint BDB format owner 0101 and format type 0005. Unknown fields are
// ignored; all required PIV fields and their encoded sizes are checked.
func ParseBiometricInformation(data []byte) (BiometricInformation, error) {
	result := BiometricInformation{Raw: data}
	count := -1

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return BiometricInformation{}, fmt.Errorf("%w: BIT group: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x02:
			if count != -1 || len(value) != 1 || value[0] > 2 {
				return BiometricInformation{}, fmt.Errorf("%w: BIT group count", ErrInvalidResponse)
			}

			count = int(value[0])
		case 0x7f60:
			if len(result.Templates) == 2 {
				return BiometricInformation{}, fmt.Errorf("%w: too many PIV BITs", ErrInvalidResponse)
			}

			template, err := parseBiometricInformationTemplate(value)
			if err != nil {
				return BiometricInformation{}, err
			}

			if template.Reference != PrimaryFingerOCC+KeyReference(len(result.Templates)) {
				return BiometricInformation{}, fmt.Errorf("%w: BIT reference order", ErrInvalidResponse)
			}

			result.Templates = append(result.Templates, template)
		}
	}

	if count != len(result.Templates) {
		return BiometricInformation{}, fmt.Errorf("%w: BIT group count mismatch", ErrInvalidResponse)
	}

	return result, nil
}

func parseBiometricInformationTemplate(data []byte) (BiometricInformationTemplate, error) {
	result := BiometricInformationTemplate{Raw: data}

	var haveReference, haveHeader bool

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return BiometricInformationTemplate{}, fmt.Errorf("%w: BIT: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x83:
			if haveReference || len(value) != 1 {
				return BiometricInformationTemplate{}, fmt.Errorf("%w: BIT reference", ErrInvalidResponse)
			}

			result.Reference, haveReference = KeyReference(value[0]), true
		case 0xa1:
			if haveHeader {
				return BiometricInformationTemplate{}, fmt.Errorf("%w: duplicate BIT header", ErrInvalidResponse)
			}

			if err := parseBiometricInformationHeader(value, &result); err != nil {
				return BiometricInformationTemplate{}, err
			}

			haveHeader = true
		}
	}

	if !haveReference || !haveHeader {
		return BiometricInformationTemplate{}, fmt.Errorf("%w: incomplete BIT", ErrInvalidResponse)
	}

	return result, nil
}

func parseBiometricInformationHeader(data []byte, result *BiometricInformationTemplate) error {
	var seen byte

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return fmt.Errorf("%w: BIT header: %v", ErrInvalidResponse, err)
		}

		data = rest

		var bit byte

		switch tag {
		case 0x81:
			bit = 1

			if len(value) != 1 || value[0] != 0x08 {
				return fmt.Errorf("%w: BIT biometric type", ErrInvalidResponse)
			}
		case 0x82:
			bit = 2

			if len(value) != 1 {
				return fmt.Errorf("%w: BIT finger subtype", ErrInvalidResponse)
			}

			result.Finger = BiometricSubtype(value[0])
		case 0x87, 0x88:
			if len(value) != 2 {
				return fmt.Errorf("%w: BIT format", ErrInvalidResponse)
			}

			if tag == 0x87 {
				bit, result.FormatOwner = 4, binary.BigEndian.Uint16(value)
			} else {
				bit, result.FormatType = 8, binary.BigEndian.Uint16(value)
			}
		case 0xb1:
			bit = 16

			if err := parseBiometricInformationParameters(value, result); err != nil {
				return err
			}
		default:
			continue
		}

		if seen&bit != 0 {
			return fmt.Errorf("%w: duplicate BIT header field", ErrInvalidResponse)
		}

		seen |= bit
	}

	if seen != 31 || result.FormatOwner != 0x0101 || result.FormatType != 0x0005 {
		return fmt.Errorf("%w: incomplete or unsupported PIV BIT format", ErrInvalidResponse)
	}

	return nil
}

func parseBiometricInformationParameters(data []byte, result *BiometricInformationTemplate) error {
	var haveLimits, haveOrder bool

	for len(data) != 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return fmt.Errorf("%w: BIT parameters: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x81:
			if haveLimits || len(value) != 2 || value[0] > value[1] {
				return fmt.Errorf("%w: BIT minutiae limits", ErrInvalidResponse)
			}

			result.MinutiaeMinimum, result.MinutiaeMaximum, haveLimits = value[0], value[1], true
		case 0x82:
			if haveOrder || len(value) != 1 {
				return fmt.Errorf("%w: BIT minutiae order", ErrInvalidResponse)
			}

			result.MinutiaeOrder, haveOrder = value[0], true
		case 0x83:
			return fmt.Errorf("%w: PIV BIT feature handling indicator", ErrInvalidResponse)
		}
	}

	if !haveLimits || !haveOrder {
		return fmt.Errorf("%w: incomplete BIT parameters", ErrInvalidResponse)
	}

	return nil
}
