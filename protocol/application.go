package protocol

import (
	"fmt"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/iso7816"
)

// ApplicationPropertyTemplate describes the application selected by SELECT
// (SP 800-73-5 Part 2, Sec. 3.1.1, Tables 3-5). AID and
// TagAllocationAuthorityAID retain the identifiers in tags 4F and 79/4F without
// joining or normalizing them. Some cards report their PIX and RID separately.
// Algorithm identifiers are retained even when this package does not know them.
// The byte slices borrow the parsed response.
type ApplicationPropertyTemplate struct {
	AID                       []byte
	TagAllocationAuthorityAID []byte
	ApplicationLabel          string
	ApplicationURL            string
	Algorithms                []Algorithm
}

// SelectCommand selects the PIV application by its nine-byte AID prefix.
func SelectCommand() iso7816.Command {
	return iso7816.Command{
		INS: byte(Select), P1: 0x04,
		Data: []byte{0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00},
		Le:   256, Encoding: iso7816.EncodingShort,
	}
}

// ParseApplicationPropertyTemplate parses a complete SELECT response template,
// including its outer tag 61. The application and tag allocation authority
// identifiers are mandatory. Unknown fields are ignored. Optional metadata is
// left empty when absent; the parser does not infer supported algorithms.
func ParseApplicationPropertyTemplate(data []byte) (ApplicationPropertyTemplate, error) {
	data, err := ParseObject(data, 0x61)
	if err != nil {
		return ApplicationPropertyTemplate{}, err
	}

	var (
		application                                ApplicationPropertyTemplate
		haveAID, haveAuthority, haveLabel, haveURL bool
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return ApplicationPropertyTemplate{}, fmt.Errorf("%w: application properties: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x4f:
			if haveAID || len(value) == 0 || len(value) > 16 {
				return ApplicationPropertyTemplate{}, fmt.Errorf("%w: invalid application identifier", ErrInvalidResponse)
			}

			application.AID, haveAID = value, true
		case 0x79:
			if haveAuthority {
				return ApplicationPropertyTemplate{}, fmt.Errorf("%w: duplicate tag allocation authority", ErrInvalidResponse)
			}

			application.TagAllocationAuthorityAID, err = parseTagAllocationAuthority(value)
			if err != nil {
				return ApplicationPropertyTemplate{}, err
			}

			haveAuthority = true
		case 0x50:
			if haveLabel {
				return ApplicationPropertyTemplate{}, fmt.Errorf("%w: duplicate application label", ErrInvalidResponse)
			}

			application.ApplicationLabel, haveLabel = string(value), true
		case 0x5f50:
			if haveURL {
				return ApplicationPropertyTemplate{}, fmt.Errorf("%w: duplicate application URL", ErrInvalidResponse)
			}

			application.ApplicationURL, haveURL = string(value), true
		case 0xac:
			// Cards report either one AC per algorithm or several 80 fields
			// in a single AC. Preserve their order without deduplication.
			algorithms, err := parseApplicationAlgorithms(value)
			if err != nil {
				return ApplicationPropertyTemplate{}, err
			}

			application.Algorithms = append(application.Algorithms, algorithms...)
		}
	}

	if !haveAID {
		return ApplicationPropertyTemplate{}, fmt.Errorf("%w: missing application identifier", ErrInvalidResponse)
	}

	if !haveAuthority {
		return ApplicationPropertyTemplate{}, fmt.Errorf("%w: missing tag allocation authority", ErrInvalidResponse)
	}

	return application, nil
}

func parseTagAllocationAuthority(data []byte) ([]byte, error) {
	var aid []byte

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%w: tag allocation authority: %v", ErrInvalidResponse, err)
		}

		data = rest

		if tag == 0x4f {
			if aid != nil || len(value) == 0 || len(value) > 16 {
				return nil, fmt.Errorf("%w: invalid tag allocation authority identifier", ErrInvalidResponse)
			}

			aid = value
		}
	}

	if aid == nil {
		return nil, fmt.Errorf("%w: missing tag allocation authority identifier", ErrInvalidResponse)
	}

	return aid, nil
}

func parseApplicationAlgorithms(data []byte) ([]Algorithm, error) {
	var (
		algorithms []Algorithm
		haveOID    bool
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%w: application algorithms: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x80:
			if len(value) != 1 {
				return nil, fmt.Errorf("%w: invalid application algorithm identifier", ErrInvalidResponse)
			}

			algorithms = append(algorithms, Algorithm(value[0]))
		case 0x06:
			if haveOID || len(value) != 1 || value[0] != 0 {
				return nil, fmt.Errorf("%w: invalid application algorithm object identifier", ErrInvalidResponse)
			}

			haveOID = true
		}
	}

	if len(algorithms) == 0 || !haveOID {
		return nil, fmt.Errorf("%w: incomplete cryptographic algorithm template", ErrInvalidResponse)
	}

	return algorithms, nil
}
