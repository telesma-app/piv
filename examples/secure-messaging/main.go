package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/telesma-app/iso7816"
	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport/sm"
)

func main() {
	reader := flag.String("reader", "", "exact PC/SC reader name (required)")
	caFile := flag.String("ca", "", "independently trusted content-signing CA certificates in PEM (required)")
	intermediateFile := flag.String("intermediates", "", "content-signing intermediate CA certificates in PEM")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for the complete operation")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if err := run(ctx, *reader, *caFile, *intermediateFile); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, reader, caFile, intermediateFile string) (err error) {
	if reader == "" || caFile == "" {
		return errors.New("-reader and -ca are required")
	}

	// Trust anchors must come from an independent source, not from the card.
	roots, err := readCertificates(caFile)
	if err != nil {
		return err
	}

	intermediates := x509.NewCertPool()
	if intermediateFile != "" {
		intermediates, err = readCertificates(intermediateFile)
		if err != nil {
			return err
		}
	}

	connection, err := pivpcsc.Open(ctx, reader)
	if err != nil {
		return err
	}

	closeSession := connection.Close
	defer func() {
		err = errors.Join(err, closeSession())
	}()

	signerData, err := client.NewClient(connection).GetSecureMessagingCertificateSigner(ctx)
	if err != nil {
		return fmt.Errorf("read content signer: %w", err)
	}

	signer, err := x509.ParseCertificate(signerData.CertificateDER)
	if err != nil {
		return err
	}

	trust, err := sm.TrustFromCertificate(signer, x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates,
	}, signerData.IntermediateCVC)
	if err != nil {
		return err
	}

	channel, err := sm.Open(ctx, connection, sm.Parameters{
		Trust:       trust,
		CipherSuite: protocol.CipherSuite7,
		Encoding:    iso7816.EncodingShort,
	})
	if err != nil {
		return err
	}

	// The channel now owns the connection; Device takes ownership of the channel.
	device := card.New(channel)
	closeSession = device.Close

	data, err := device.GetData(ctx, protocol.CardCapabilityContainer)
	if err != nil {
		return err
	}

	_, err = fmt.Printf("CS7 protected CCC: %d bytes\n", len(data))

	return err
}

func readCertificates(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("%s contains no PEM certificates", path)
	}

	return pool, nil
}
