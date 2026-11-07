package pcsc_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// TestPIVHardware only issues SELECT, empty VERIFY, and GET DATA. It never
// submits reference data, changes card contents, or performs key operations.
func TestPIVHardware(t *testing.T) {
	if os.Getenv("PIV_TEST") != "1" {
		t.Skip("set PIV_TEST=1 to run the read-only hardware test")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	selectedReader := os.Getenv("PIV_READER")

	var tested int

	for reader, err := range nativepcsc.Enumerate() {
		if err != nil {
			t.Fatal(err)
		}

		if selectedReader != "" && reader.Name != selectedReader {
			continue
		}

		if reader.State&nativepcsc.ReaderStatePresent == 0 {
			t.Logf("reader %q: no card", reader.Name)
			continue
		}

		found, err := testPIVCard(t, ctx, reader.Name)
		if err != nil {
			t.Errorf("reader %q: %v", reader.Name, err)
		}

		if found {
			tested++
		}
	}

	if tested == 0 {
		t.Fatal("no PIV card found; connect a USB CCID token or present it to a PC/SC reader")
	}
}

func testPIVCard(t *testing.T, ctx context.Context, reader string) (found bool, err error) {
	t.Helper()

	device, err := pivpcsc.Open(ctx, reader)
	if hardwareObjectNotFound(err) {
		t.Logf("reader %q: PIV application absent", reader)
		return false, nil
	}

	if err != nil {
		return false, err
	}
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	c := client.NewClient(device)

	properties, err := c.Select(ctx)
	if err != nil {
		return true, err
	}

	t.Logf("reader %q: application properties=%x", reader, properties)

	status, err := c.ReferenceStatus(ctx, protocol.ApplicationPIN)
	if err != nil {
		return true, fmt.Errorf("PIN status: %w", err)
	}

	t.Logf("application PIN: verified=%t retries=%d", status.Verified, status.Retries)

	var result error

	for _, object := range []protocol.Object{
		protocol.CardCapabilityContainer,
		protocol.CardholderUniqueIdentifier,
		protocol.DiscoveryObject,
	} {
		data, err := c.GetData(ctx, object)
		if hardwareObjectNotFound(err) {
			t.Logf("object %x: absent", uint32(object))
			continue
		}

		if err != nil {
			result = errors.Join(result, fmt.Errorf("GET DATA %x: %w", uint32(object), err))
			continue
		}

		t.Logf("object %x: %d bytes", uint32(object), len(data))
	}

	for _, key := range []protocol.KeyReference{
		protocol.PIVAuthentication,
		protocol.DigitalSignature,
		protocol.KeyManagement,
		protocol.CardAuthentication,
	} {
		certificate, err := c.GetCertificate(ctx, key)
		if hardwareObjectNotFound(err) {
			t.Logf("certificate %02x: absent", byte(key))
			continue
		}

		if err != nil {
			result = errors.Join(result, fmt.Errorf("read certificate %02x: %w", byte(key), err))
			continue
		}

		t.Logf("certificate %02x: %s, %d bytes", byte(key), certificate.PublicKeyAlgorithm, len(certificate.Raw))
	}

	return true, result
}

func hardwareObjectNotFound(err error) bool {
	var apduError *iso7816.APDUError
	return errors.As(err, &apduError) && apduError.StatusWord() == 0x6a82
}
