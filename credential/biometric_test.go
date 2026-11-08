package credential

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509/pkix"
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

func TestVerifyBiometricRequiresSingleSignerAndDigest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := newSigningFixture(t, key)
	chuid := fixtureCHUID(t, fixture)

	for _, tc := range []struct {
		name   string
		modify func(*signedData)
	}{
		{name: "multiple signers", modify: func(signed *signedData) {
			signed.Signers = append(signed.Signers, signed.Signers[0])
		}},
		{name: "multiple digests", modify: func(signed *signedData) {
			signed.Digests = append(signed.Digests, pkix.AlgorithmIdentifier{Algorithm: oidSHA384, Parameters: asn1.NullRawValue})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			biometric := fixtureBiometric(t, fixture, chuid, false, nil)
			if _, err := VerifyBiometric(biometric, chuid, fixture.options); err != nil {
				t.Fatalf("valid biometric: %v", err)
			}

			// Changing CMS cardinality changes the signed CBEFF footer length.
			// With fixed-size RSA signatures, the second pass signs that final length.
			for range 2 {
				md := sha256.Sum256(biometric.SignedData)
				attrs := []fixtureAttribute{
					fixtureAttr(t, oidContentType, oidBiometric), fixtureAttr(t, oidMessageDigest, md[:]), fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawSubject}),
					fixtureAttr(t, oidFASCN, chuid.FASCN[:]), fixtureAttr(t, oidEntryUUID, chuid.GUID[:]),
				}

				signed, err := parseCMS(fixtureCMS(t, fixture, biometric.SignedData, oidBiometric, false, false, attrs, nil))
				if err != nil {
					t.Fatal(err)
				}

				tc.modify(&signed)
				biometric.Signature = encodeCMSFixture(t, signed)

				biometric, err = protocol.ParseBiometricData(protocol.EncodeBiometricData(biometric))
				if err != nil {
					t.Fatal(err)
				}
			}

			signed, err := parseCMS(biometric.Signature)
			if err != nil {
				t.Fatal(err)
			}

			for _, signer := range signed.Signers {
				if _, err := verifyCMSSigner(signed, signer, fixture.cert, biometric.SignedData, oidBiometric, true); err != nil {
					t.Fatalf("fixture signature does not authenticate the final CBEFF bytes: %v", err)
				}
			}

			certificate, err := VerifyBiometric(biometric, chuid, fixture.options)
			if !errors.Is(err, ErrAuthentication) {
				t.Errorf("VerifyBiometric = %v, want ErrAuthentication", err)
			}

			if certificate != nil {
				t.Error("VerifyBiometric returned a signer for an invalid CMS profile")
			}
		})
	}
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

func TestVerifyBiometricRequiresMatchingFASCN(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := newSigningFixture(t, key)
	chuid := fixtureCHUID(t, fixture)
	foreign := chuid.FASCN
	foreign[0] ^= 1

	for _, tc := range []struct {
		name   string
		header [25]byte
		signed [25]byte
	}{
		{name: "signed attribute", header: chuid.FASCN, signed: foreign},
		{name: "CBEFF header", header: foreign, signed: chuid.FASCN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			biometric := fixtureBiometric(t, fixture, chuid, false, nil)
			if _, err := VerifyBiometric(biometric, chuid, fixture.options); err != nil {
				t.Fatalf("valid biometric: %v", err)
			}

			biometric.Header.FASCN = tc.header

			biometric, err := protocol.ParseBiometricData(protocol.EncodeBiometricData(biometric))
			if err != nil {
				t.Fatal(err)
			}

			// Both identifiers have fixed width, and RSA signatures have fixed
			// size, so re-signing preserves the CBEFF footer length.
			md := sha256.Sum256(biometric.SignedData)
			attrs := []fixtureAttribute{
				fixtureAttr(t, oidContentType, oidBiometric), fixtureAttr(t, oidMessageDigest, md[:]), fixtureAttr(t, oidSignerDN, asn1.RawValue{FullBytes: fixture.cert.RawSubject}),
				fixtureAttr(t, oidFASCN, tc.signed[:]), fixtureAttr(t, oidEntryUUID, chuid.GUID[:]),
			}
			biometric.Signature = fixtureCMS(t, fixture, biometric.SignedData, oidBiometric, false, false, attrs, nil)

			biometric, err = protocol.ParseBiometricData(protocol.EncodeBiometricData(biometric))
			if err != nil {
				t.Fatal(err)
			}

			signed, err := parseCMS(biometric.Signature)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := verifyCMS(signed, fixture.cert, biometric.SignedData, oidBiometric, true); err != nil {
				t.Fatalf("fixture does not authenticate its final CBEFF bytes: %v", err)
			}

			certificate, err := VerifyBiometric(biometric, chuid, fixture.options)
			if !errors.Is(err, ErrAuthentication) {
				t.Errorf("VerifyBiometric = %v, want ErrAuthentication", err)
			}

			if certificate != nil {
				t.Error("VerifyBiometric returned a signer for a foreign FASC-N")
			}
		})
	}
}
