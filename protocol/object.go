package protocol

import (
	"fmt"

	"github.com/telesma-app/piv/internal/bertlv"
)

// ParseObject reads an exact single object with the expected tag.
func ParseObject(data []byte, tag uint32) ([]byte, error) {
	got, value, rest, err := bertlv.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if got != tag || len(rest) != 0 {
		return nil, fmt.Errorf("%w: expected single tag %x, got %x", ErrInvalidResponse, tag, got)
	}

	return value, nil
}
