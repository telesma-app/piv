package credential

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"testing"

	"github.com/telesma-app/piv/protocol"
)

func TestVerifySecurityObjectAndEveryDataGroup(t *testing.T) {
	fixture := newSigningFixture(t, nil)
	data := map[protocol.ContainerID][]byte{0xdb00: {0xf5, 1, 0x10}, 0x3001: {1, 1, 'A'}}

	var hashes []protocol.DataGroupHash

	for i, container := range []protocol.ContainerID{0xdb00, 0x3001} {
		md := sha256.Sum256(data[container])
		hashes = append(hashes, protocol.DataGroupHash{DataGroup: uint8(i + 1), Digest: md[:]})
	}

	der, err := protocol.EncodeLDSSecurityObject(protocol.LDSSecurityObject{HashAlgorithm: crypto.SHA256, Hashes: hashes})
	if err != nil {
		t.Fatal(err)
	}

	for _, oid := range []asn1.ObjectIdentifier{oidLDS, oidLDSLegacy} {
		object := protocol.SecurityObjectData{Mapping: []protocol.DataGroupMapping{{DataGroup: 1, ContainerID: 0xdb00}, {DataGroup: 2, ContainerID: 0x3001}}, SignedData: fixtureCMS(t, fixture, der, oid, false, true, nil, nil)}

		lds, err := VerifySecurityObject(object, fixture.cert, fixture.options)
		if err != nil {
			t.Fatal(err)
		}

		if err := VerifyDataGroups(object, lds, data); err != nil {
			t.Fatal(err)
		}

		if err := VerifyDataGroups(object, lds, map[protocol.ContainerID][]byte{0xdb00: data[0xdb00]}); !errors.Is(err, ErrIntegrity) {
			t.Errorf("missing container = %v", err)
		}

		if err := VerifyDataGroups(object, lds, map[protocol.ContainerID][]byte{0xdb00: data[0xdb00], 0x3001: []byte("changed")}); !errors.Is(err, ErrIntegrity) {
			t.Errorf("changed container = %v", err)
		}

		object.Mapping[1].DataGroup = 3
		if _, err := VerifySecurityObject(object, fixture.cert, fixture.options); !errors.Is(err, ErrAuthentication) {
			t.Errorf("mapping mismatch = %v", err)
		}
	}
}

func TestVerifyDataGroups(t *testing.T) {
	for _, algorithm := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
		t.Run(algorithm.String(), func(t *testing.T) {
			object := protocol.SecurityObjectData{Mapping: []protocol.DataGroupMapping{
				{DataGroup: 1, ContainerID: 0xdb00},
				{DataGroup: 2, ContainerID: 0x3001},
			}}
			first := algorithm.New()
			first.Write([]byte("abc"))

			second := algorithm.New()
			lds := protocol.LDSSecurityObject{HashAlgorithm: algorithm, Hashes: []protocol.DataGroupHash{
				{DataGroup: 2, Digest: second.Sum(nil)},
				{DataGroup: 1, Digest: first.Sum(nil)},
			}}

			for _, tc := range []struct {
				name string
				data map[protocol.ContainerID][]byte
				want *DataGroupError
			}{
				{name: "all containers", data: map[protocol.ContainerID][]byte{0xdb00: []byte("abc"), 0x3001: nil}},
				{name: "empty container", data: map[protocol.ContainerID][]byte{0xdb00: []byte("abc"), 0x3001: {}}},
				{name: "extra container", data: map[protocol.ContainerID][]byte{0xdb00: []byte("abc"), 0x3001: nil, 0x6030: []byte("ignored")}},
				{name: "missing first container", data: map[protocol.ContainerID][]byte{0x3001: nil}, want: &DataGroupError{ContainerID: 0xdb00, Missing: true}},
				{name: "missing second container", data: map[protocol.ContainerID][]byte{0xdb00: []byte("abc")}, want: &DataGroupError{ContainerID: 0x3001, Missing: true}},
				{name: "changed first container", data: map[protocol.ContainerID][]byte{0xdb00: []byte("abd"), 0x3001: nil}, want: &DataGroupError{ContainerID: 0xdb00}},
				{name: "changed second container", data: map[protocol.ContainerID][]byte{0xdb00: []byte("abc"), 0x3001: {0}}, want: &DataGroupError{ContainerID: 0x3001}},
				{name: "present empty first container", data: map[protocol.ContainerID][]byte{0xdb00: nil, 0x3001: nil}, want: &DataGroupError{ContainerID: 0xdb00}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					err := VerifyDataGroups(object, lds, tc.data)
					if tc.want == nil {
						if err != nil {
							t.Fatalf("VerifyDataGroups = %v", err)
						}

						return
					}

					var got *DataGroupError
					if !errors.Is(err, ErrIntegrity) || !errors.As(err, &got) {
						t.Fatalf("VerifyDataGroups = %v, want DataGroupError wrapping ErrIntegrity", err)
					}

					if *got != *tc.want {
						t.Errorf("DataGroupError = %+v, want %+v", *got, *tc.want)
					}
				})
			}
		})
	}
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
