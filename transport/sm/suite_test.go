package sm

import (
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func testCipherSuite(t testing.TB, algorithm protocol.Algorithm) cipherSuite {
	t.Helper()

	suite, err := selectCipherSuite(algorithm)
	if err != nil {
		t.Fatal(err)
	}

	return suite
}

func testCipherSuites(t *testing.T, run func(*testing.T, cipherSuite)) {
	t.Helper()

	for _, test := range []struct {
		name      string
		algorithm protocol.Algorithm
	}{
		{name: "CS2", algorithm: protocol.CipherSuite2},
		{name: "CS7", algorithm: protocol.CipherSuite7},
	} {
		t.Run(test.name, func(t *testing.T) { run(t, testCipherSuite(t, test.algorithm)) })
	}
}
