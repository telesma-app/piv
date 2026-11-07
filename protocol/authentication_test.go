package protocol

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestDynamicAuthenticationEncoding(t *testing.T) {
	tests := []struct {
		name string
		auth DynamicAuthentication
		wire []byte
	}{
		{
			name: "absent fields",
			wire: []byte{0x7c, 0x00},
		},
		{
			name: "empty witness request",
			auth: DynamicAuthentication{Witness: []byte{}},
			wire: []byte{0x7c, 0x02, 0x80, 0x00},
		},
		{
			name: "sign request",
			auth: DynamicAuthentication{Challenge: []byte{1, 2, 3}, Response: []byte{}},
			wire: []byte{0x7c, 0x07, 0x82, 0x00, 0x81, 0x03, 1, 2, 3},
		},
		{
			name: "mutual authentication",
			auth: DynamicAuthentication{Witness: []byte{1}, Challenge: []byte{2}, Response: []byte{}},
			wire: []byte{0x7c, 0x08, 0x80, 0x01, 1, 0x81, 0x01, 2, 0x82, 0x00},
		},
		{
			name: "all fields",
			auth: DynamicAuthentication{
				Witness: []byte{1}, Challenge: []byte{2},
				Response: []byte{3}, Exponentiation: []byte{4},
			},
			wire: []byte{0x7c, 0x0c, 0x80, 0x01, 1, 0x81, 0x01, 2, 0x82, 0x01, 3, 0x85, 0x01, 4},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.auth.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(wire, tt.wire) {
				t.Errorf("wire = %x, want %x", wire, tt.wire)
			}

			auth, err := ParseDynamicAuthentication(tt.wire)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(auth, tt.auth) {
				t.Errorf("authentication = %#v, want %#v", auth, tt.auth)
			}
		})
	}
}

func TestParseDynamicAuthenticationIgnoresUnknownFields(t *testing.T) {
	data := []byte{0x7c, 0x08, 0x83, 0x03, 1, 2, 3, 0x82, 0x01, 4}

	auth, err := ParseDynamicAuthentication(data)
	if err != nil {
		t.Fatal(err)
	}

	if want := (DynamicAuthentication{Response: []byte{4}}); !reflect.DeepEqual(auth, want) {
		t.Errorf("authentication = %#v, want %#v", auth, want)
	}
}

func TestParseDynamicAuthenticationRejectsInvalidTemplates(t *testing.T) {
	tests := []struct {
		name string
		wire []byte
	}{
		{name: "wrong wrapper", wire: []byte{0x53, 0x00}},
		{name: "trailing bytes", wire: []byte{0x7c, 0x00, 0x82, 0x00}},
		{name: "truncated field", wire: []byte{0x7c, 0x02, 0x82, 0x01}},
		{name: "duplicate witness", wire: []byte{0x7c, 0x04, 0x80, 0x00, 0x80, 0x00}},
		{name: "duplicate challenge", wire: []byte{0x7c, 0x04, 0x81, 0x00, 0x81, 0x00}},
		{name: "duplicate response", wire: []byte{0x7c, 0x04, 0x82, 0x00, 0x82, 0x00}},
		{name: "duplicate exponentiation", wire: []byte{0x7c, 0x04, 0x85, 0x00, 0x85, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseDynamicAuthentication(tt.wire)
			if !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
