package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"time"

	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

func main() {
	reader := flag.String("reader", "", "exact PC/SC reader name (required)")
	commonName := flag.String("cn", "", "CSR subject common name (required)")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for CSR creation")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if err := run(ctx, *reader, *commonName); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, reader, commonName string) (err error) {
	if reader == "" {
		return errors.New("-reader is required")
	}

	if commonName == "" {
		return errors.New("-cn is required")
	}

	pin := os.Getenv("PIV_PIN")
	if pin == "" {
		return errors.New("PIV_PIN is required")
	}

	connection, err := pivpcsc.Open(ctx, reader)
	if err != nil {
		return err
	}

	device := card.New(connection)
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	// Read the matching certificate to bind the existing slot key.
	certificate, err := device.GetCertificate(ctx, protocol.DigitalSignature)
	if err != nil {
		return err
	}

	key, err := device.PrivateKey(protocol.DigitalSignature, certificate.PublicKey)
	if err != nil {
		return err
	}

	// The signer verifies the PIN together with each signing operation.
	authentication := card.PINAuthentication(protocol.ApplicationPIN, func(context.Context) (string, error) {
		return pin, nil
	})
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}

	der, err := x509.CreateCertificateRequest(rand.Reader, template, key.Signer(ctx, authentication))
	if err != nil {
		return err
	}

	return pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
