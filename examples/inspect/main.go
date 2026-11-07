package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/telesma-app/iso7816"
	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

func main() {
	reader := flag.String("reader", "", "exact PC/SC reader name; default: inspect all inserted cards")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for the complete inspection")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if err := run(ctx, *reader); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, reader string) error {
	if reader != "" {
		_, err := inspect(ctx, reader)
		return err
	}

	var (
		result    error
		inspected int
	)

	for reader, err := range pivpcsc.Devices(ctx) {
		if err != nil {
			return errors.Join(result, err)
		}

		fmt.Printf("reader: %q, ATR: %x\n", reader.Name, reader.ATR)

		found, err := inspect(ctx, reader.Name)
		if found {
			inspected++
		}

		if err != nil {
			if !found && objectNotFound(err) {
				fmt.Printf("reader %q: PIV application absent\n", reader.Name)
				continue
			}

			result = errors.Join(result, fmt.Errorf("reader %q: %w", reader.Name, err))
		}
	}

	if inspected == 0 {
		result = errors.Join(result, errors.New("no PIV card inspected"))
	}

	return result
}

func inspect(ctx context.Context, reader string) (found bool, err error) {
	connection, err := pivpcsc.Open(ctx, reader)
	if err != nil {
		return false, err
	}

	device := card.New(connection)
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	return true, inspectCard(ctx, os.Stdout, reader, device)
}

func inspectCard(ctx context.Context, out io.Writer, reader string, device *card.Device) error {
	_, _ = fmt.Fprintf(out, "PIV reader: %q\n", reader)
	if application, ok := device.ApplicationProperties(); ok {
		_, _ = fmt.Fprintf(out, "reader %q: application %q, AID %x, algorithms %x\n",
			reader, application.ApplicationLabel, application.AID, application.Algorithms)
	}

	var result error

	status, err := device.ReferenceStatus(ctx, protocol.ApplicationPIN)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("query application PIN status: %w", err))
		if !readCanContinue(err) {
			return result
		}

		_, _ = fmt.Fprintf(out, "reader %q: application PIN status: %v\n", reader, err)
	} else if status.Verified {
		_, _ = fmt.Fprintf(out, "reader %q: application PIN: verified\n", reader)
	} else {
		_, _ = fmt.Fprintf(out, "reader %q: application PIN: %d retries remaining\n", reader, status.Retries)
	}

	for _, object := range []struct {
		name string
		tag  protocol.Object
	}{
		{name: "CCC", tag: protocol.CardCapabilityContainer},
		{name: "CHUID", tag: protocol.CardholderUniqueIdentifier},
		{name: "discovery", tag: protocol.DiscoveryObject},
	} {
		data, err := device.GetData(ctx, object.tag)
		if objectNotFound(err) {
			_, _ = fmt.Fprintf(out, "reader %q: %s: absent\n", reader, object.name)
			continue
		}

		if err != nil {
			result = errors.Join(result, fmt.Errorf("read %s: %w", object.name, err))
			if !readCanContinue(err) {
				return result
			}

			_, _ = fmt.Fprintf(out, "reader %q: %s: %v\n", reader, object.name, err)

			continue
		}

		_, _ = fmt.Fprintf(out, "reader %q: %s: %d bytes\n", reader, object.name, len(data))
	}

	history, historyErr := device.GetKeyHistory(ctx)
	if objectNotFound(historyErr) {
		_, _ = fmt.Fprintf(out, "reader %q: key history: absent\n", reader)
	} else if historyErr != nil {
		result = errors.Join(result, fmt.Errorf("read key history: %w", historyErr))
		if !readCanContinue(historyErr) {
			return result
		}

		_, _ = fmt.Fprintf(out, "reader %q: key history: %v\n", reader, historyErr)
	} else {
		_, _ = fmt.Fprintf(out, "reader %q: retired keys: %d with on-card certificates, %d with off-card certificates\n",
			reader, history.KeysWithOnCardCerts, history.KeysWithOffCardCerts)

		if history.OffCardCertURL != "" {
			_, _ = fmt.Fprintf(out, "reader %q: off-card certificate URL: %q\n", reader, history.OffCardCertURL)
		}
	}

	for entry, err := range device.Certificates(ctx) {
		if objectNotFound(err) {
			location := "absent"
			if historyErr == nil && history.KeysWithOffCardCerts != 0 &&
				entry.Key <= protocol.RetiredKey20 &&
				entry.Key > protocol.RetiredKey20-protocol.KeyReference(history.KeysWithOffCardCerts) {
				location = "off-card"
			}

			_, _ = fmt.Fprintf(out, "reader %q: certificate %02x: %s\n", reader, byte(entry.Key), location)

			continue
		}

		if err != nil {
			_, _ = fmt.Fprintf(out, "reader %q: certificate %02x: %d DER bytes, %v\n", reader, byte(entry.Key), len(entry.DER), err)
			result = errors.Join(result, fmt.Errorf("read certificate %02x: %w", byte(entry.Key), err))

			continue
		}

		certificate := entry.Certificate
		_, _ = fmt.Fprintf(out, "reader %q: certificate %02x: %s, %d DER bytes, valid %s to %s\n",
			reader, byte(entry.Key), certificate.PublicKeyAlgorithm, len(entry.DER),
			certificate.NotBefore.UTC().Format(time.RFC3339), certificate.NotAfter.UTC().Format(time.RFC3339))
	}

	return result
}

func objectNotFound(err error) bool {
	var apduError *iso7816.APDUError
	return readCanContinue(err) && errors.As(err, &apduError) && apduError.StatusWord() == 0x6a82
}

func readCanContinue(err error) bool {
	var (
		invalidated *transport.DeviceInvalidatedError
		ioError     *transport.IOError
	)
	if errors.As(err, &invalidated) || errors.As(err, &ioError) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.ErrClosedPipe) {
		return false
	}

	var apdu *iso7816.APDUError

	return errors.As(err, &apdu) || errors.Is(err, protocol.ErrInvalidResponse)
}
