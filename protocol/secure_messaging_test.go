package protocol

import (
	"bytes"
	"errors"
	"testing"
)

func TestParseSecureMessagingCertificateSigner(t *testing.T) {
	der := certificateDER(t)
	// Preserve the original long-form length, rather than re-encoding the CVC.
	intermediate := []byte{0x7f, 0x21, 0x81, 3, 0x42, 1, 0x5a}

	for _, test := range []struct {
		name         string
		certificate  []byte
		info         byte
		intermediate []byte
	}{
		{name: "direct signer", certificate: der},
		{name: "intermediate CVC", certificate: der, intermediate: intermediate},
		{name: "GZIP with uncompressed CVC", certificate: certificateGZIP(t, der), info: 1, intermediate: intermediate},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := certificateObject(test.certificate, test.info)
			data = append(data, test.intermediate...)
			data = append(data, 0x72, 1, 0xab)

			signer, err := ParseSecureMessagingCertificateSigner(data)
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(signer.CertificateDER, der) {
				t.Error("decoded certificate differs from the original DER")
			}

			if !bytes.Equal(signer.IntermediateCVC, test.intermediate) ||
				(signer.IntermediateCVC == nil) != (test.intermediate == nil) {
				t.Errorf("intermediate CVC = %x, want %x", signer.IntermediateCVC, test.intermediate)
			}
		})
	}
}

func TestSecureMessagingCertificateSignerBorrowsEncodedCVC(t *testing.T) {
	data := certificateObject([]byte{1, 2, 3}, 0)
	start := len(data)
	data = append(data, 0x7f, 0x21, 0x81, 3, 0x42, 1, 0x5a, 0x72, 1, 0xab)

	signer, err := ParseSecureMessagingCertificateSigner(data)
	if err != nil {
		t.Fatal(err)
	}

	if &signer.IntermediateCVC[0] != &data[start] {
		t.Error("intermediate CVC does not borrow the encoded object")
	}

	if cap(signer.IntermediateCVC) != len(signer.IntermediateCVC) {
		t.Error("appending to the intermediate CVC could overwrite another field")
	}
}

func TestParseSecureMessagingCertificateSignerRejectsInvalidObject(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "missing certificate", data: []byte{0x71, 1, 0}},
		{name: "invalid certificate encoding", data: certificateObject([]byte{1}, 2)},
		{name: "invalid GZIP", data: certificateObject([]byte{1}, 1)},
		{name: "truncated CVC", data: append(certificateObject([]byte{1}, 0), 0x7f, 0x21, 2, 0)},
		{name: "duplicate CVC", data: append(certificateObject([]byte{1}, 0), 0x7f, 0x21, 0, 0x7f, 0x21, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseSecureMessagingCertificateSigner(test.data); !errors.Is(err, ErrInvalidResponse) {
				t.Errorf("parse error = %v, want ErrInvalidResponse", err)
			}
		})
	}
}
