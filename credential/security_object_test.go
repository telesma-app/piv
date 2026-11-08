package credential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func securityObjectKeyID(t testing.TB, cms []byte, subjectKeyID []byte) []byte {
	t.Helper()

	signed, err := parseCMS(cms)
	if err != nil {
		t.Fatal(err)
	}
	// SID is not part of the signed attributes. Change the identifier while
	// retaining the independently generated signature and exact attributes.
	signed.Signers[0].Raw = nil
	signed.Signers[0].Version = 3
	signed.Signers[0].SID = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: subjectKeyID}

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

func TestSecurityObjectDigestAndSignerProfiles(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		hash  crypto.Hash
	}{{elliptic.P256(), crypto.SHA256}, {elliptic.P384(), crypto.SHA384}} {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			fixture := newSigningFixture(t, key)
			chuid := fixtureCHUID(t, fixture)

			signer, err := VerifyCHUID(chuid, fixture.options)
			if err != nil {
				t.Fatal(err)
			}

			data := map[protocol.ContainerID][]byte{0xdb00: {0xf5, 1, 0x10}, 0x3001: {1, 1, 'A'}}

			list := protocol.LDSSecurityObject{HashAlgorithm: tc.hash}
			for i, id := range []protocol.ContainerID{0xdb00, 0x3001} {
				hash := tc.hash.New()
				hash.Write(data[id])
				list.Hashes = append(list.Hashes, protocol.DataGroupHash{DataGroup: uint8(i + 1), Digest: hash.Sum(nil)})
			}

			body, err := protocol.EncodeLDSSecurityObject(list)
			if err != nil {
				t.Fatal(err)
			}

			cms := fixtureCMS(t, fixture, body, oidLDS, false, true, nil, nil)
			for _, keyID := range []bool{false, true} {
				wire := cms
				if keyID {
					wire = securityObjectKeyID(t, cms, fixture.cert.SubjectKeyId)
				}

				object := protocol.SecurityObjectData{Mapping: []protocol.DataGroupMapping{{DataGroup: 1, ContainerID: 0xdb00}, {DataGroup: 2, ContainerID: 0x3001}}, SignedData: wire}

				lds, err := VerifySecurityObject(object, signer, fixture.options)
				if err != nil {
					t.Fatal(err)
				}

				if lds.HashAlgorithm != tc.hash {
					t.Errorf("LDS digest = %v, want %v", lds.HashAlgorithm, tc.hash)
				}

				if err := VerifyDataGroups(object, lds, data); err != nil {
					t.Fatal(err)
				}

				if keyID {
					wrongKeyID := bytes.Clone(fixture.cert.SubjectKeyId)
					wrongKeyID[0] ^= 1

					object.SignedData = securityObjectKeyID(t, cms, wrongKeyID)
					if _, err := VerifySecurityObject(object, signer, fixture.options); !errors.Is(err, ErrAuthentication) {
						t.Errorf("wrong subject key ID accepted: %v", err)
					}
				}
			}
		})
	}
}
