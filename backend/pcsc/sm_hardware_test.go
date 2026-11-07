package pcsc_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
	nativepcsc "github.com/telesma-app/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	piviso7816 "github.com/telesma-app/piv/transport/iso7816"
	"github.com/telesma-app/piv/transport/sm"
)

// TestSMHardware selects PIV, reads public objects, and establishes ephemeral
// CS7 sessions. It never submits a PIN/pairing code, signs, writes or generates
// keys. CA material must come from a source trusted independently of the card.
func TestSMHardware(t *testing.T) {
	if os.Getenv("PIV_SM_TEST") != "1" {
		t.Skip("set PIV_SM_TEST=1, PIV_READER and PIV_SM_CA_FILE for read-only CS7 verification")
	}

	reader, caFile := os.Getenv("PIV_READER"), os.Getenv("PIV_SM_CA_FILE")
	if reader == "" || caFile == "" {
		t.Fatal("PIV_READER and independently trusted PIV_SM_CA_FILE are required")
	}

	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("CA file contains no certificates")
	}

	intermediates := x509.NewCertPool()

	if file := os.Getenv("PIV_SM_INTERMEDIATE_FILE"); file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		if !intermediates.AppendCertsFromPEM(data) {
			t.Fatal("intermediate file contains no certificates")
		}
	}

	for _, encoding := range []iso7816.Encoding{iso7816.EncodingShort, iso7816.EncodingExtended} {
		name := "short"
		if encoding == iso7816.EncodingExtended {
			name = "extended"
		}

		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			raw, err := nativepcsc.Open(reader,
				nativepcsc.WithShareMode(nativepcsc.ShareModeExclusive),
				nativepcsc.WithDisconnectDisposition(nativepcsc.DispositionResetCard),
			)
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = raw.Close() })

			wire := &smHardwareCard{Card: raw}

			connection, err := piviso7816.Open(ctx, wire)
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = connection.Close() })

			c := client.NewClient(connection)

			properties, err := c.Select(ctx)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("reader=%q application=%q algorithms=%x", reader, properties.ApplicationLabel, properties.Algorithms)

			objects := []protocol.Object{
				protocol.DiscoveryObject, protocol.CardCapabilityContainer,
				protocol.CardholderUniqueIdentifier, protocol.SecureMessagingCertificateSignerObject,
			}
			baseline := make(map[protocol.Object][]byte)

			for _, object := range objects {
				data, err := c.GetData(ctx, object)
				if err != nil {
					t.Fatalf("plaintext GET DATA %x: %v", object, err)
				}

				baseline[object] = data
			}

			signerData, err := protocol.ParseSecureMessagingCertificateSigner(baseline[protocol.SecureMessagingCertificateSignerObject])
			if err != nil {
				t.Fatal(err)
			}

			signer, err := x509.ParseCertificate(signerData.CertificateDER)
			if err != nil {
				t.Fatal(err)
			}

			trust, err := sm.TrustFromCertificate(signer, x509.VerifyOptions{Roots: roots, Intermediates: intermediates}, signerData.IntermediateCVC)
			if err != nil {
				t.Fatal(err)
			}

			t.Logf("validated content signer: issuer=%q SHA256=%x", signer.Issuer.CommonName, sha256.Sum256(signer.Raw))

			channel, err := sm.Open(ctx, connection, sm.Parameters{
				Trust: trust, CipherSuite: protocol.CipherSuite7, Encoding: encoding,
			})
			if err != nil {
				t.Fatal(err)
			}

			device := card.New(channel)

			t.Cleanup(func() { _ = device.Close() })

			wire.protected = true

			for range 2 {
				for _, object := range objects {
					data, err := device.GetData(ctx, object)
					if err != nil {
						t.Fatalf("protected GET DATA %x: %v", object, err)
					}

					if !bytes.Equal(data, baseline[object]) {
						t.Fatalf("protected object %x differs from plaintext baseline", object)
					}

					t.Logf("protected object %x: %d bytes", object, len(data))
				}
			}

			if encoding == iso7816.EncodingShort && wire.getResponses == 0 {
				t.Fatal("public signer read did not exercise response assembly")
			}

			t.Logf("authenticated CS7 exchanges=8 plaintext framing GET RESPONSE=%d", wire.getResponses)
		})
	}
}

type smHardwareCard struct {
	*nativepcsc.Card
	protected    bool
	getResponses int
}

func (c *smHardwareCard) Transmit(ctx context.Context, apdu []byte) ([]byte, error) {
	if c.protected && apdu[1] == 0xc0 {
		c.getResponses++

		if apdu[0] != 0 {
			return nil, iso7816.ErrInvalidCommand
		}
	}

	return c.Card.Transmit(ctx, apdu)
}
