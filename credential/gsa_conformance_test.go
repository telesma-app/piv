package credential

import (
	"bytes"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/telesma-app/piv/protocol"
)

func TestGSASignedObjects(t *testing.T) {
	// Independent public GSA card-builder output; provenance is recorded in
	// testdata/gsa/README.md. Its certificate asserts a public test policy, so
	// authenticate signatures here and separately reject production trust.
	read := func(name string) []byte {
		t.Helper()

		data, err := os.ReadFile(filepath.Join("..", "testdata", "gsa", "card46-"+name+".bin"))
		if err != nil {
			t.Fatal(err)
		}

		return data
	}

	chuid, err := protocol.ParseCHUID(read("chuid"))
	if err != nil {
		t.Fatal(err)
	}

	cms, err := parseCMS(chuid.IssuerSignature)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := cmsCertificate(cms, nil, true)
	if err != nil {
		t.Fatal(err)
	}

	content := bytes.Clone(chuid.Raw[:79])

	content = append(content, 0xfe, 0)
	if _, err := verifyCMS(cms, signer, content, oidCHUID, true); err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(signer)

	if _, err := VerifyCHUID(chuid, x509.VerifyOptions{Roots: roots, CurrentTime: signer.NotBefore.Add(time.Hour)}); !errors.Is(err, ErrAuthentication) {
		t.Errorf("GSA test certificate accepted as production content signer: %v", err)
	}

	object, err := protocol.ParseSecurityObject(read("security-object"))
	if err != nil {
		t.Fatal(err)
	}

	signed, err := parseCMS(object.SignedData)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := cmsCertificate(signed, signer, false); err != nil {
		t.Fatal(err)
	}

	if _, err := verifyCMS(signed, signer, signed.Content.Content, oidLDSLegacy, false); err != nil {
		t.Fatal(err)
	}

	lds, err := protocol.ParseLDSSecurityObject(signed.Content.Content)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyDataGroups(object, lds, map[protocol.ContainerID][]byte{0x3000: read("chuid"), 0x6030: read("face"), 0x6010: read("fingerprints"), 0x3001: read("printed-information")}); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"face", "fingerprints"} {
		biometric, err := protocol.ParseBiometricData(read(name))
		if err != nil {
			t.Fatal(err)
		}

		signed, err := parseCMS(biometric.Signature)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := cmsCertificate(signed, signer, false); err != nil {
			t.Fatal(err)
		}

		attrs, err := verifyCMS(signed, signer, biometric.SignedData, oidBiometric, true)
		if err != nil {
			t.Fatal(err)
		}

		var fascn, guid []byte
		if err := attributeValue(attrs, oidFASCN, &fascn); err != nil {
			t.Fatal(err)
		}

		if err := attributeValue(attrs, oidEntryUUID, &guid); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(fascn, chuid.FASCN[:]) || !bytes.Equal(guid, chuid.GUID[:]) {
			t.Errorf("GSA %s signed identifiers differ from CHUID", name)
		}
	}
}
