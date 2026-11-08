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

	"github.com/telesma-app/piv/protocol"
)

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
