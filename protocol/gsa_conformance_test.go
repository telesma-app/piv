package protocol

import (
	"bytes"
	"os"
	"testing"
)

func TestFacialImageRecordGSAInteroperability(t *testing.T) {
	data, err := os.ReadFile("../testdata/gsa/card46-face.bin")
	if err != nil {
		t.Fatal(err)
	}

	object, err := ParseBiometricData(data)
	if err != nil {
		t.Fatal(err)
	}

	record, err := ParseFacialImageRecord(object.Record)
	if err != nil {
		t.Fatal(err)
	}

	if len(record.Images) != 1 {
		t.Fatalf("GSA face images = %d", len(record.Images))
	}

	image := record.Images[0]
	if image.Width != 200 || image.Height != 162 || image.ImageDataType != 1 || image.ImageType != 1 || image.ColorSpace != 1 || image.SourceType != 2 || len(image.Image) != 5398 {
		t.Fatalf("GSA facial metadata = %+v", image)
	}
	// JPEG2000 file signature is preserved, without an image decoder dependency.
	if !bytes.Equal(image.Image[:12], []byte{0, 0, 0, 12, 'j', 'P', ' ', ' ', 13, 10, 135, 10}) || !bytes.Equal(EncodeFacialImageRecord(record), object.Record) {
		t.Error("GSA face compressed image or metadata changed")
	}
}

func TestFingerprintRecordGSAInteroperability(t *testing.T) {
	data, err := os.ReadFile("../testdata/gsa/card46-fingerprints.bin")
	if err != nil {
		t.Fatal(err)
	}

	object, err := ParseBiometricData(data)
	if err != nil {
		t.Fatal(err)
	}

	record, err := ParseFingerprintRecord(object.Record)
	if err != nil {
		t.Fatal(err)
	}

	if record.ProductOwner != 1 || record.ProductType != 1 || record.CaptureEquipment != 0x8001 || record.Width != 512 || record.Height != 480 || len(record.Views) != 2 || record.Views[0].Finger != FingerLeftIndex || len(record.Views[0].Minutiae) != 41 {
		t.Fatalf("GSA fingerprint metadata = %+v", record)
	}

	if !bytes.Equal(EncodeFingerprintRecord(record), object.Record) {
		t.Error("GSA fingerprint round trip changed wire bytes")
	}
}

func TestFASCNGSAInterop(t *testing.T) {
	// This unchanged public GSA test credential is an independent oracle;
	// its provenance is recorded in testdata/gsa/README.md. Its LRC is A,
	// which is a valid four-bit check value even though data digits are decimal.
	data, err := os.ReadFile("../testdata/gsa/card46-chuid.bin")
	if err != nil {
		t.Fatal(err)
	}

	chuid, err := ParseCHUID(data)
	if err != nil {
		t.Fatal(err)
	}

	want := FASCN{
		AgencyCode: "4700", SystemCode: "0257", CredentialNumber: "000046",
		CredentialSeries: "1", IndividualCredentialIssue: "1", PersonIdentifier: "0257000046",
		OrganizationalCategory: "1", OrganizationalIdentifier: "9999", PersonOrganizationAssociation: "1",
	}

	got, err := ParseFASCN(chuid.FASCN[:])
	if err != nil {
		t.Fatal(err)
	}

	if got != want {
		t.Errorf("ParseFASCN = %+v, want %+v", got, want)
	}

	encoded, err := EncodeFASCN(want)
	if err != nil {
		t.Fatal(err)
	}

	if encoded != chuid.FASCN {
		t.Errorf("EncodeFASCN = %x, want GSA %x", encoded, chuid.FASCN)
	}
}
