package credential

import (
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestVerifyOffCardKeyHistoryFile(t *testing.T) {
	// SHA-256's published "abc" test vector checks integrity independently of
	// the DER parser; this function authenticates exact bytes of any encoding.
	const url = "http://example.test/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

	if err := VerifyOffCardKeyHistoryFile(url, []byte("abc")); err != nil {
		t.Fatal(err)
	}

	for _, data := range [][]byte{[]byte("abd"), []byte("abc\x00"), nil} {
		if err := VerifyOffCardKeyHistoryFile(url, data); !errors.Is(err, ErrIntegrity) {
			t.Errorf("VerifyOffCardKeyHistoryFile(%x) = %v, want ErrIntegrity", data, err)
		}
	}

	if err := VerifyOffCardKeyHistoryFile("http://example.test/invalid", []byte("abc")); !errors.Is(err, protocol.ErrInvalidResponse) {
		t.Errorf("malformed URL = %v, want protocol.ErrInvalidResponse", err)
	}
}
