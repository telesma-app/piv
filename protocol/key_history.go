package protocol

import (
	"fmt"

	"github.com/telesma-app/piv/internal/bertlv"
)

// KeyHistory describes retired key management keys. Certificates stored on the
// card occupy the lowest retired key references; keys with off-card certificates
// occupy the highest. OffCardCertURL may also identify certificates stored on
// the card. It is returned without fetching or establishing trust in its content.
type KeyHistory struct {
	KeysWithOnCardCerts  uint8
	KeysWithOffCardCerts uint8
	OffCardCertURL       string
}

// EncodeKeyHistory encodes a Key History object's content without the outer 53
// template, for PutData (SP 800-73-5 Part 1, Table 20). It preserves the supplied
// counts and URL without validation or normalization. An empty URL omits tag F3.
func EncodeKeyHistory(history KeyHistory) []byte {
	data := []byte{0xc1, 1, history.KeysWithOnCardCerts, 0xc2, 1, history.KeysWithOffCardCerts}
	if history.OffCardCertURL != "" {
		data = bertlv.Append(data, 0xf3, []byte(history.OffCardCertURL))
	}

	return append(data, 0xfe, 0)
}

// ParseKeyHistory parses a Key History object value without its outer 0x53
// wrapper (SP 800-73-5 Part 1, Sec. 3.3.3 and Table 20). Unknown fields are
// ignored. The URL is retained as an opaque ASCII value for the caller.
func ParseKeyHistory(data []byte) (KeyHistory, error) {
	var (
		history                                   KeyHistory
		haveOnCard, haveOffCard, haveURL, haveEDC bool
	)

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return KeyHistory{}, fmt.Errorf("%w: key history: %v", ErrInvalidResponse, err)
		}

		data = rest

		switch tag {
		case 0xc1:
			if haveOnCard || len(value) != 1 || value[0] > 20 {
				return KeyHistory{}, fmt.Errorf("%w: invalid on-card certificate count", ErrInvalidResponse)
			}

			history.KeysWithOnCardCerts, haveOnCard = value[0], true
		case 0xc2:
			if haveOffCard || len(value) != 1 || value[0] > 20 {
				return KeyHistory{}, fmt.Errorf("%w: invalid off-card certificate count", ErrInvalidResponse)
			}

			history.KeysWithOffCardCerts, haveOffCard = value[0], true
		case 0xf3:
			if haveURL || len(value) == 0 || len(value) > 118 {
				return KeyHistory{}, fmt.Errorf("%w: invalid off-card certificate URL", ErrInvalidResponse)
			}

			for _, b := range value {
				if b < 0x21 || b > 0x7e {
					return KeyHistory{}, fmt.Errorf("%w: non-ASCII off-card certificate URL", ErrInvalidResponse)
				}
			}

			history.OffCardCertURL, haveURL = string(value), true
		case 0xfe:
			if haveEDC || len(value) != 0 {
				return KeyHistory{}, fmt.Errorf("%w: invalid key history error detection code", ErrInvalidResponse)
			}

			haveEDC = true
		}
	}

	if !haveOnCard || !haveOffCard {
		return KeyHistory{}, fmt.Errorf("%w: missing key history certificate count", ErrInvalidResponse)
	}

	if history.KeysWithOnCardCerts+history.KeysWithOffCardCerts > 20 {
		return KeyHistory{}, fmt.Errorf("%w: key history exceeds 20 retired keys", ErrInvalidResponse)
	}

	if history.KeysWithOffCardCerts != 0 && !haveURL {
		return KeyHistory{}, fmt.Errorf("%w: missing off-card certificate URL", ErrInvalidResponse)
	}

	if history.KeysWithOnCardCerts == 0 && history.KeysWithOffCardCerts == 0 && haveURL {
		return KeyHistory{}, fmt.Errorf("%w: off-card certificate URL without retired keys", ErrInvalidResponse)
	}

	return history, nil
}
