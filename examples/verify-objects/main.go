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

	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/credential"
	"github.com/telesma-app/piv/protocol"
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

	roots, err := readCertificates(caFile)
	if err != nil {
		return err
	}

	options := x509.VerifyOptions{Roots: roots}
	if intermediateFile != "" {
		options.Intermediates, err = readCertificates(intermediateFile)
		if err != nil {
			return err
		}
	}

	connection, err := pivpcsc.Open(ctx, reader)
	if err != nil {
		return err
	}

	device := card.New(connection)
	defer func() { err = errors.Join(err, device.Close()) }()

	chuid, err := device.GetCHUID(ctx)
	if err != nil {
		return err
	}

	signer, err := credential.VerifyCHUID(chuid, options)
	if err != nil {
		return err
	}

	security, err := device.GetSecurityObject(ctx)
	if err != nil {
		return err
	}

	lds, err := credential.VerifySecurityObject(security, signer, options)
	if err != nil {
		return err
	}

	// Some mapped objects require PIN activation. Submit only an explicitly
	// supplied PIN; an incorrect value consumes a retry and is not retried.
	if pin := os.Getenv("PIV_PIN"); pin != "" {
		if err := device.VerifyPIN(ctx, pin); err != nil {
			return err
		}
	}

	objects := make(map[protocol.ContainerID][]byte, len(security.Mapping))
	for _, entry := range security.Mapping {
		object, err := protocol.ObjectForContainerID(entry.ContainerID)
		if err != nil {
			return err
		}

		data, err := device.GetData(ctx, object)
		if err != nil {
			return err
		}

		objects[entry.ContainerID] = data
	}

	if err := credential.VerifyDataGroups(security, lds, objects); err != nil {
		return err
	}

	_, err = fmt.Printf("Verified CHUID, Security Object and %d data-group digests\n", len(security.Mapping))

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
