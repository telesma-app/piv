package pcsc_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/iso7816/scp11"
	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// TestSCP11Hardware only selects applications, retrieves certificates, establishes
// a channel, and reads PIV data. It never submits a PIN or changes stored data.
func TestSCP11Hardware(t *testing.T) {
	if os.Getenv("PIV_SCP11_TEST") != "1" {
		t.Skip("set PIV_SCP11_TEST=1, PIV_READER, and a trusted PIV_SCP11_CA_FILE or PIV_SCP11_PEER_KEY")
	}

	reader := os.Getenv("PIV_READER")
	if reader == "" {
		t.Fatal("PIV_READER must identify the card under test")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	connection, err := pivpcsc.Open(ctx, reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	var peerKey *ecdh.PublicKey

	if encoded := os.Getenv("PIV_SCP11_PEER_KEY"); encoded != "" {
		point, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}

		peerKey, err = ecdh.P256().NewPublicKey(point)
		if err != nil {
			t.Fatal(err)
		}
	} else {
		caFile := os.Getenv("PIV_SCP11_CA_FILE")
		if caFile == "" {
			t.Fatal("supply a previously trusted CA file or static peer key; card certificates alone are not trusted")
		}

		pem, err := os.ReadFile(caFile)
		if err != nil {
			t.Fatal(err)
		}

		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			t.Fatal("trusted CA file contains no certificates")
		}

		certificates, err := scp11.ReadCertificates(ctx, connection, 1, 0x13)
		if err != nil {
			t.Fatal(err)
		}

		intermediates := x509.NewCertPool()

		if file := os.Getenv("PIV_SCP11_INTERMEDIATE_FILE"); file != "" {
			pem, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}

			if !intermediates.AppendCertsFromPEM(pem) {
				t.Fatal("intermediate file contains no certificates")
			}
		}

		for _, certificate := range certificates[:len(certificates)-1] {
			intermediates.AddCert(certificate)
		}

		leaf := certificates[len(certificates)-1]
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots: roots, Intermediates: intermediates,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			t.Fatalf("untrusted SCP11 certificate (issuer %q, %d card certificates): %v", leaf.Issuer.CommonName, len(certificates), err)
		}

		publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("SCP11 leaf has public key type %T", leaf.PublicKey)
		}

		peerKey, err = publicKey.ECDH()
		if err != nil {
			t.Fatal(err)
		}
	}

	if _, err := client.NewClient(connection).Select(ctx); err != nil {
		t.Fatal(err)
	}

	channel, err := scp11.Open(ctx, connection, scp11.Parameters{
		KeyID: 0x13, KeyVersion: 1, PeerKey: peerKey, Encoding: iso7816.EncodingExtended,
	})
	if err != nil {
		t.Fatal(err)
	}

	device := card.New(channel)

	t.Cleanup(func() { _ = device.Close() })

	// Discovery is a small response, while a populated certificate exercises
	// encrypted multi-part responses and plaintext framing GET RESPONSE.
	first, err := device.GetData(ctx, protocol.DiscoveryObject)
	if err != nil {
		t.Fatal(err)
	}

	second, err := device.GetData(ctx, protocol.DiscoveryObject)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("sequential protected reads differ: %v", err)
	}

	t.Logf("authenticated SCP11b: discovery=%d bytes", len(first))

	if encoded := os.Getenv("PIV_SCP11_CERTIFICATE_SLOT"); encoded != "" {
		slot, err := strconv.ParseUint(encoded, 16, 8)
		if err != nil {
			t.Fatal(err)
		}

		der, err := device.GetCertificateDER(ctx, protocol.KeyReference(slot))
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("protected certificate %02x: %d DER bytes", slot, len(der))
	}
}
