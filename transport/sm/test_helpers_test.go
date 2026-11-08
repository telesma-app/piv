package sm

import (
	"encoding/hex"
	"testing"
)

func decodeHex(t testing.TB, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}
