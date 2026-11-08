package credential

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/telesma-app/bertlv"
	"github.com/telesma-app/piv/protocol"
)

func encodeCMSFixture(t testing.TB, signed signedData) []byte {
	t.Helper()

	body, err := asn1.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}

	der, err := asn1.Marshal(contentInfo{Type: oidSignedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: body}})
	if err != nil {
		t.Fatal(err)
	}

	return der
}

func cmsFixtureSigner(t testing.TB, wire []byte) signerInfo {
	t.Helper()

	signed, err := parseCMS(wire)
	if err != nil {
		t.Fatal(err)
	}

	return signed.Signers[0]
}

func TestSecurityObjectSelectedSigners(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := newSigningFixture(t, key)
	list := protocol.LDSSecurityObject{HashAlgorithm: crypto.SHA256, Hashes: []protocol.DataGroupHash{{DataGroup: 1, Digest: make([]byte, 32)}, {DataGroup: 2, Digest: make([]byte, 32)}}}

	body, err := protocol.EncodeLDSSecurityObject(list)
	if err != nil {
		t.Fatal(err)
	}

	wire := fixtureCMS(t, fixture, body, oidLDS, false, true, nil, nil)

	base, err := parseCMS(wire)
	if err != nil {
		t.Fatal(err)
	}

	selected := base.Signers[0]
	object := protocol.SecurityObjectData{Mapping: []protocol.DataGroupMapping{{DataGroup: 1, ContainerID: 0xdb00}, {DataGroup: 2, ContainerID: 0x3001}}}

	for _, serial := range []int64{1, 3} {
		// The other certificate is intentionally not supplied. Its issuer DN
		// equals the selected signer's issuer; only its serial differs. An
		// unrelated signature is not authenticated by this operation.
		unrelated := selected
		unrelated.Raw = nil

		sid, err := issuerAndSerial(unrelated)
		if err != nil {
			t.Fatal(err)
		}

		sid.Serial = big.NewInt(serial)

		der, err := asn1.Marshal(sid)
		if err != nil {
			t.Fatal(err)
		}

		unrelated.SID = asn1.RawValue{FullBytes: der}
		unrelated.Signature = bytes.Repeat([]byte{0x55}, len(selected.Signature))
		combined := base
		combined.Signers = []signerInfo{selected, unrelated}
		object.SignedData = encodeCMSFixture(t, combined)

		parsed, err := parseCMS(object.SignedData)
		if err != nil {
			t.Fatal(err)
		}

		firstSelected, err := signerMatchesCertificate(parsed.Signers[0], fixture.cert)
		if err != nil {
			t.Fatal(err)
		}

		if firstSelected != (serial == 3) {
			t.Fatal("fixture does not exercise selected signer before and after unrelated signer")
		}

		if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); err != nil {
			t.Errorf("unrelated serial %d: %v", serial, err)
		}

		combined.Signers = []signerInfo{unrelated}

		object.SignedData = encodeCMSFixture(t, combined)
		if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); !errors.Is(err, ErrAuthentication) {
			t.Errorf("missing selected signer accepted: %v", err)
		}
	}

	keyID := cmsFixtureSigner(t, securityObjectKeyID(t, wire, fixture.cert.SubjectKeyId))
	combined := base
	combined.Signers = []signerInfo{selected, keyID}

	object.SignedData = encodeCMSFixture(t, combined)
	if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); err != nil {
		t.Errorf("two valid selected signers rejected: %v", err)
	}

	for _, index := range []int{0, 1} {
		combined.Signers = []signerInfo{selected, keyID}
		combined.Signers[index].Raw = nil
		combined.Signers[index].Signature = bytes.Clone(combined.Signers[index].Signature)
		combined.Signers[index].Signature[0] ^= 1

		object.SignedData = encodeCMSFixture(t, combined)
		if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); !errors.Is(err, ErrAuthentication) {
			t.Errorf("invalid selected signature %d accepted despite another valid match: %v", index, err)
		}
	}

	sha384Fixture := fixture
	sha384Fixture.hash = crypto.SHA384
	sha384 := cmsFixtureSigner(t, fixtureCMS(t, sha384Fixture, body, oidLDS, false, true, nil, nil))
	combined.Signers = []signerInfo{selected, sha384}

	combined.Digests = append([]pkix.AlgorithmIdentifier(nil), base.Digests...)
	combined.Digests = append(combined.Digests, pkix.AlgorithmIdentifier{Algorithm: oidSHA384, Parameters: asn1.NullRawValue})

	object.SignedData = encodeCMSFixture(t, combined)
	if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); !errors.Is(err, ErrAuthentication) {
		t.Errorf("selected signers with conflicting digest algorithms accepted: %v", err)
	}

	combined.Signers = []signerInfo{sha384}

	object.SignedData = encodeCMSFixture(t, combined)
	if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); !errors.Is(err, ErrAuthentication) {
		t.Errorf("selected signer digest differing from LDS accepted: %v", err)
	}
}

func TestCMSDigestSetMembership(t *testing.T) {
	fixture := newSigningFixture(t, nil)

	base, err := parseCMS(fixtureCMS(t, fixture, []byte("content"), oidLDS, false, true, nil, nil))
	if err != nil {
		t.Fatal(err)
	}

	for _, digests := range [][]pkix.AlgorithmIdentifier{
		nil,
		{{Algorithm: oidSHA384}},
		{{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}}},
	} {
		signed := base

		signed.Digests = digests
		if _, err := parseCMS(encodeCMSFixture(t, signed)); !errors.Is(err, ErrAuthentication) {
			t.Errorf("invalid digest set accepted: %v", err)
		}
	}

	base.Signers = nil
	if _, err := parseCMS(encodeCMSFixture(t, base)); !errors.Is(err, ErrAuthentication) {
		t.Errorf("empty signer set accepted: %v", err)
	}
}

func TestCHUIDAndBiometricRequireSingleSignerAndDigest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := newSigningFixture(t, key)
	chuid := fixtureCHUID(t, fixture)
	biometric := fixtureBiometric(t, fixture, chuid, false, nil)

	for _, duplicateSigner := range []bool{false, true} {
		modify := func(wire []byte) []byte {
			signed, err := parseCMS(wire)
			if err != nil {
				t.Fatal(err)
			}

			if duplicateSigner {
				signed.Signers = append(signed.Signers, signed.Signers[0])
			} else {
				signed.Digests = append(signed.Digests, pkix.AlgorithmIdentifier{Algorithm: oidSHA384, Parameters: asn1.NullRawValue})
			}

			return encodeCMSFixture(t, signed)
		}

		var content []byte

		for data := chuid.Raw; len(data) != 0; {
			tag, _, rest, err := bertlv.Parse(data)
			if err != nil {
				t.Fatal(err)
			}

			if tag == 0x3e {
				content = bertlv.Append(content, tag, modify(chuid.IssuerSignature))
			} else {
				content = append(content, data[:len(data)-len(rest)]...)
			}

			data = rest
		}

		invalidCHUID, err := protocol.ParseCHUID(content)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := VerifyCHUID(invalidCHUID, fixture.options); !errors.Is(err, ErrAuthentication) {
			t.Errorf("CHUID multi signer/digest accepted: %v", err)
		}

		invalidBiometric := biometric
		invalidBiometric.Signature = modify(biometric.Signature)

		invalidBiometric, err = protocol.ParseBiometricData(protocol.EncodeBiometricData(invalidBiometric))
		if err != nil {
			t.Fatal(err)
		}

		if _, err := VerifyBiometric(invalidBiometric, chuid, fixture.options); !errors.Is(err, ErrAuthentication) {
			t.Errorf("biometric multi signer/digest accepted: %v", err)
		}
	}
}
