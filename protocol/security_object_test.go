package protocol

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
)

func TestSecurityObjectWire(t *testing.T) {
	// BA consists of three-byte DG/container entries, not GET DATA tags.
	wire := []byte{0xba, 6, 1, 0xdb, 0, 2, 0x30, 1, 0xbb, 2, 0x30, 0, 0xfe, 0}

	object, err := ParseSecurityObject(wire)
	if err != nil {
		t.Fatal(err)
	}

	if len(object.Mapping) != 2 || object.Mapping[0] != (DataGroupMapping{DataGroup: 1, ContainerID: 0xdb00}) || object.Mapping[1] != (DataGroupMapping{DataGroup: 2, ContainerID: 0x3001}) {
		t.Fatalf("mapping = %+v", object.Mapping)
	}

	if got := EncodeSecurityObject(object); !bytes.Equal(got, wire) {
		t.Errorf("encoded = %x, want %x", got, wire)
	}

	object.SignedData[1] = 1

	if wire[11] != 1 {
		t.Error("signature does not borrow source bytes")
	}
}

func TestSecurityObjectMalformed(t *testing.T) {
	for _, wire := range [][]byte{
		{}, {0xba, 0, 0xbb, 1, 1}, {0xba, 2, 1, 2, 0xbb, 1, 1},
		{0xba, 3, 0, 0x30, 0, 0xbb, 1, 1},
		{0xba, 6, 1, 0x30, 0, 1, 0x30, 1, 0xbb, 1, 1},
		{0xba, 6, 1, 0x30, 0, 2, 0x30, 0, 0xbb, 1, 1},
		{0xba, 3, 1, 0x30, 0, 0xbb, 0},
		{0xba, 3, 1, 0x30, 0, 0xbb, 1, 1, 0xfe, 1, 0},
	} {
		if _, err := ParseSecurityObject(wire); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("ParseSecurityObject(%x) = %v", wire, err)
		}
	}
}

func TestLDSSecurityObject(t *testing.T) {
	// Independently encode the ICAO ASN.1 profile without production structs.
	for _, tc := range []struct {
		name    string
		hash    crypto.Hash
		oidLast byte
		version byte
	}{
		{name: "SHA256 version 0", hash: crypto.SHA256, oidLast: 1},
		{name: "SHA256 version 1", hash: crypto.SHA256, oidLast: 1, version: 1},
		{name: "SHA384 version 0", hash: crypto.SHA384, oidLast: 2},
		{name: "SHA384 version 1", hash: crypto.SHA384, oidLast: 2, version: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			algorithm := []byte{0x30, 0x0b, 6, 9, 0x60, 0x86, 0x48, 1, 0x65, 3, 4, 2, tc.oidLast}
			group := func(n byte) []byte {
				return append([]byte{0x30, byte(5 + tc.hash.Size()), 2, 1, n, 4, byte(tc.hash.Size())}, bytes.Repeat([]byte{n}, tc.hash.Size())...)
			}
			groups := append([]byte{0x30, byte(2 * (7 + tc.hash.Size()))}, group(1)...)
			groups = append(groups, group(2)...)
			content := append([]byte{2, 1, tc.version}, algorithm...)

			content = append(content, groups...)
			if tc.version == 1 {
				content = append(content, 0x30, 13, 0x13, 4, '0', '1', '0', '8', 0x13, 5, '0', '4', '0', '0', '0')
			}

			wire := []byte{0x30}
			if len(content) >= 128 {
				wire = append(wire, 0x81)
			}

			wire = append(wire, byte(len(content)))
			wire = append(wire, content...)

			object, err := ParseLDSSecurityObject(wire)
			if err != nil {
				t.Fatal(err)
			}

			if object.HashAlgorithm != tc.hash || len(object.Hashes) != 2 {
				t.Fatalf("LDS = %+v, want %v and two hashes", object, tc.hash)
			}

			for i, hash := range object.Hashes {
				if hash.DataGroup != uint8(i+1) || !bytes.Equal(hash.Digest, bytes.Repeat([]byte{byte(i + 1)}, tc.hash.Size())) {
					t.Errorf("hash %d = %+v", i, hash)
				}
			}

			if (object.VersionInfo != nil) != (tc.version == 1) {
				t.Fatal("version information presence differs")
			}

			if object.VersionInfo != nil && *object.VersionInfo != (LDSVersionInfo{LDSVersion: "0108", UnicodeVersion: "04000"}) {
				t.Errorf("version information = %+v", object.VersionInfo)
			}

			encoded, err := EncodeLDSSecurityObject(object)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(encoded, wire) {
				t.Errorf("LDS encoded = %x, want %x", encoded, wire)
			}
		})
	}
}

func TestLDSRejectsMalformedDigestLists(t *testing.T) {
	base := LDSSecurityObject{HashAlgorithm: crypto.SHA384, Hashes: []DataGroupHash{{DataGroup: 1, Digest: make([]byte, 48)}, {DataGroup: 2, Digest: make([]byte, 48)}}}

	wire, err := EncodeLDSSecurityObject(base)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseLDSSecurityObject(wire); err != nil {
		t.Fatalf("valid SHA384 digest list: %v", err)
	}

	for _, modify := range []func(*LDSSecurityObject){
		func(o *LDSSecurityObject) { o.Hashes = o.Hashes[:1] },
		func(o *LDSSecurityObject) { o.Hashes[0].DataGroup = 0 },
		func(o *LDSSecurityObject) { o.Hashes[1].DataGroup = 1 },
		func(o *LDSSecurityObject) { o.Hashes[0].Digest = make([]byte, 32) },
	} {
		object := base
		object.Hashes = append([]DataGroupHash(nil), base.Hashes...)
		modify(&object)

		wire, err := EncodeLDSSecurityObject(object)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := ParseLDSSecurityObject(wire); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("malformed LDS accepted: %x (%v)", wire, err)
		}
	}

	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(wire, &raw); err != nil {
		t.Fatal(err)
	}

	raw.FullBytes = nil
	raw.Bytes = append(raw.Bytes, 5, 0)

	wire, err = asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseLDSSecurityObject(wire); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("extra LDS field accepted: %v", err)
	}
}

func TestLDSSecurityObjectProfile(t *testing.T) {
	sha256 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}}
	sha256Null := pkix.AlgorithmIdentifier{Algorithm: sha256.Algorithm, Parameters: asn1.NullRawValue}
	sha256Boolean := pkix.AlgorithmIdentifier{Algorithm: sha256.Algorithm, Parameters: asn1.RawValue{FullBytes: []byte{1, 1, 0xff}}}
	sha512 := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}}

	for _, tc := range []struct {
		name      string
		version   int
		withInfo  bool
		algorithm pkix.AlgorithmIdentifier
		valid     bool
	}{
		{name: "version 0", algorithm: sha256, valid: true},
		{name: "version 1", version: 1, withInfo: true, algorithm: sha256, valid: true},
		{name: "NULL parameters", algorithm: sha256Null, valid: true},
		{name: "unsupported version", version: 2, algorithm: sha256},
		{name: "version 0 with version info", withInfo: true, algorithm: sha256},
		{name: "version 1 without version info", version: 1, algorithm: sha256},
		{name: "invalid algorithm parameters", algorithm: sha256Boolean},
		{name: "unsupported digest", algorithm: sha512},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var info asn1.RawValue
			if tc.withInfo {
				info.FullBytes = []byte{0x30, 13, 0x13, 4, '0', '1', '0', '8', 0x13, 5, '0', '4', '0', '0', '0'}
			}

			// Keep the fixture schema independent of the production ASN.1 structs.
			type group struct {
				Number int
				Digest []byte
			}

			wire, err := asn1.Marshal(struct {
				Version   int
				Algorithm pkix.AlgorithmIdentifier
				Hashes    []group
				Info      asn1.RawValue `asn1:"optional"`
			}{
				Version: tc.version, Algorithm: tc.algorithm,
				Hashes: []group{{Number: 1, Digest: bytes.Repeat([]byte{1}, 32)}, {Number: 2, Digest: bytes.Repeat([]byte{2}, 32)}},
				Info:   info,
			})
			if err != nil {
				t.Fatal(err)
			}

			_, err = ParseLDSSecurityObject(wire)
			if tc.valid {
				if err != nil {
					t.Fatalf("ParseLDSSecurityObject = %v", err)
				}
			} else if !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseLDSSecurityObject = %v, want ErrInvalidResponse", err)
			}
		})
	}
}

func TestParseSecurityObjectRejectsDuplicateFields(t *testing.T) {
	valid := []byte{0xba, 3, 1, 0xdb, 0, 0xbb, 2, 0x30, 0, 0xfe, 0}
	if _, err := ParseSecurityObject(valid); err != nil {
		t.Fatalf("valid Security Object: %v", err)
	}

	for _, tc := range []struct {
		name  string
		extra []byte
	}{
		{name: "mapping", extra: []byte{0xba, 3, 2, 0x30, 1}},
		{name: "signature", extra: []byte{0xbb, 2, 0x30, 0}},
		{name: "EDC", extra: []byte{0xfe, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := append(bytes.Clone(valid), tc.extra...)

			if _, err := ParseSecurityObject(wire); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("ParseSecurityObject = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
