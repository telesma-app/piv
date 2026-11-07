package protocol

import (
	"fmt"
	"time"

	"github.com/telesma-app/piv/internal/bertlv"
)

// CHUID contains the Card Holder Unique Identifier data object (SP 800-73-5
// Part 1, Sec. 3.1.2 and Table 10). FASCN is the encoded 25-byte FASC-N, without
// decoding its components. ExpirationDate is a calendar date at midnight UTC.
//
// Raw preserves the exact encoded object contents, including unknown fields
// and original BER length encodings, for interpreting signed content.
// Raw, CardholderUUID, and IssuerSignature borrow the parsed input. A nil
// signature means its field was absent; a non-nil empty signature means an
// unsigned placeholder.
// Parsing does not verify the CMS signature.
type CHUID struct {
	Raw             []byte
	FASCN           [25]byte
	GUID            [16]byte
	ExpirationDate  time.Time
	CardholderUUID  *[16]byte
	IssuerSignature []byte
}

// ParseCHUID parses object contents without the outer 53 template, as returned
// by GetData. FASC-N, GUID, and expiration date are required. For compatibility
// with unpersonalized PIV tokens, the signature may be absent or empty. The
// optional Cardholder UUID is preserved without enforcing a UUID version.
// Unknown and removed legacy fields are ignored.
func ParseCHUID(data []byte) (CHUID, error) {
	chuid := CHUID{Raw: data}

	var haveFASCN, haveGUID, haveDate, haveUUID, haveSignature, haveEDC bool

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return CHUID{}, fmt.Errorf("%w: CHUID: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0x30:
			if haveFASCN || len(value) != len(chuid.FASCN) {
				return CHUID{}, fmt.Errorf("%w: invalid CHUID FASC-N", ErrInvalidResponse)
			}

			chuid.FASCN, haveFASCN = [25]byte(value), true
		case 0x34:
			if haveGUID || len(value) != len(chuid.GUID) {
				return CHUID{}, fmt.Errorf("%w: invalid CHUID GUID", ErrInvalidResponse)
			}

			chuid.GUID, haveGUID = [16]byte(value), true
		case 0x35:
			if haveDate || len(value) != 8 {
				return CHUID{}, fmt.Errorf("%w: invalid CHUID expiration date", ErrInvalidResponse)
			}

			for _, b := range value {
				if b < '0' || b > '9' {
					return CHUID{}, fmt.Errorf("%w: invalid CHUID expiration date", ErrInvalidResponse)
				}
			}

			date, err := time.Parse("20060102", string(value))
			if err != nil {
				return CHUID{}, fmt.Errorf("%w: invalid CHUID expiration date", ErrInvalidResponse)
			}

			chuid.ExpirationDate, haveDate = date, true
		case 0x36:
			if haveUUID || len(value) != 16 {
				return CHUID{}, fmt.Errorf("%w: invalid CHUID cardholder UUID", ErrInvalidResponse)
			}

			chuid.CardholderUUID, haveUUID = (*[16]byte)(value), true
		case 0x3e:
			if haveSignature {
				return CHUID{}, fmt.Errorf("%w: duplicate CHUID issuer signature", ErrInvalidResponse)
			}

			chuid.IssuerSignature, haveSignature = value, true
		case 0xfe:
			if haveEDC || len(value) != 0 {
				return CHUID{}, fmt.Errorf("%w: invalid CHUID error detection code", ErrInvalidResponse)
			}

			haveEDC = true
		}
	}

	if !haveFASCN || !haveGUID || !haveDate {
		return CHUID{}, fmt.Errorf("%w: incomplete CHUID", ErrInvalidResponse)
	}

	return chuid, nil
}
