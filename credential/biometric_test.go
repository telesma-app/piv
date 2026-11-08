package credential

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/telesma-app/piv/protocol"
)

func fixtureBiometric(t testing.TB, fixture signingFixture, chuid protocol.CHUID, embedded bool, guid []byte) protocol.BiometricData {
	t.Helper()

	if guid == nil {
		guid = chuid.GUID[:]
	}

	date := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	object := protocol.BiometricData{
		Header: protocol.BiometricHeader{SecurityOptions: 0x0d, FormatOwner: 0x001b, FormatType: 0x0201, CreationDate: date, ValidFrom: date, ValidUntil: date, BiometricType: protocol.BiometricFingerprint, DataType: 0x80, Quality: -2, FASCN: chuid.FASCN},
		Record: []byte("biometric record"), Signature: []byte{0},
	}
	// RSA signatures have a fixed size. The first pass determines the CMS
	// footer length, which is part of the authenticated CBEFF header.
	for range 2 {
		parsed, err := protocol.ParseBiometricData(protocol.EncodeBiometricData(object))
		if err != nil {
			t.Fatal(err)
		}

		md := sha256.Sum256(parsed.SignedData)
		attrs := []fixtureAttribute{
			fixtureAttr(t, oidContentType, oidBiometric), fixtureAttr(t, oidMessageDigest, md[:]), fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawSubject}),
			fixtureAttr(t, oidFASCN, chuid.FASCN[:]), fixtureAttr(t, oidEntryUUID, guid),
		}
		object.Signature = fixtureCMS(t, fixture, parsed.SignedData, oidBiometric, embedded, false, attrs, nil)
	}

	parsed, err := protocol.ParseBiometricData(protocol.EncodeBiometricData(object))
	if err != nil {
		t.Fatal(err)
	}

	return parsed
}

func TestVerifyBiometricBinding(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := newSigningFixture(t, key)
	chuid := fixtureCHUID(t, fixture)
	biometric := fixtureBiometric(t, fixture, chuid, false, nil)

	certificate, err := VerifyBiometric(biometric, chuid, fixture.options)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(certificate.Raw, fixture.cert.Raw) {
		t.Error("biometric signer differs")
	}
	// The expired biometric closing date is advisory and does not invalidate
	// a correctly authenticated record/card (SP 800-76-2, Table 14, Note 5).
	if !biometric.Header.ValidUntil.Before(fixture.options.CurrentTime) {
		t.Fatal("fixture closing date is not in the past")
	}

	foreign := fixtureBiometric(t, fixture, chuid, false, bytes.Repeat([]byte{0x99}, 16))
	if _, err := VerifyBiometric(foreign, chuid, fixture.options); !errors.Is(err, ErrAuthentication) {
		t.Errorf("foreign GUID accepted: %v", err)
	}

	biometric.SignedData[88] ^= 1
	if _, err := VerifyBiometric(biometric, chuid, fixture.options); !errors.Is(err, ErrAuthentication) {
		t.Errorf("altered biometric record accepted: %v", err)
	}

	wrongProfile := fixtureBiometric(t, fixture, chuid, true, nil)
	if _, err := VerifyBiometric(wrongProfile, chuid, fixture.options); !errors.Is(err, ErrAuthentication) {
		t.Errorf("redundant same-key certificate accepted: %v", err)
	}

	differentKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	different := newSigningFixture(t, differentKey)
	options := fixture.options
	options.Roots = options.Roots.Clone()
	options.Roots.AddCert(different.cert)

	legacy := fixtureBiometric(t, different, chuid, true, nil)
	if _, err := VerifyBiometric(legacy, chuid, options); err != nil {
		t.Errorf("different embedded biometric signer rejected: %v", err)
	}
}
