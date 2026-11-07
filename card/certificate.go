package card

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/telesma-app/iso7816"
	"github.com/telesma-app/piv/protocol"
	"github.com/telesma-app/piv/transport"
)

// Certificate is the result of reading one standard PIV certificate slot.
// Key is set even when reading fails. DER contains the decoded certificate
// bytes when object decoding succeeds; Certificate is nil if X.509 parsing
// fails. The parsed certificate and DER share the same bytes. Neither proves
// that the slot contains a matching private key or that the certificate is
// trusted.
type Certificate struct {
	Key         protocol.KeyReference
	DER         []byte
	Certificate *x509.Certificate
}

// Certificates reads the four primary slots in order 9A, 9C, 9D, 9E, followed by
// all 20 retired slots, 82 through 95. Each slot is yielded, including absent
// objects (APDU 6A82), access failures, and malformed certificates. A parsing
// failure preserves any successfully decoded DER and does not stop the scan.
// I/O failures, invalidation, closure, cancellation, and unknown transport errors
// are yielded once for the current slot and stop enumeration.
//
// Reads are lazy and do not prefetch. The operation gate is released before
// yielding; callbacks may call Device methods. Each slot is read independently,
// so this is not an atomic snapshot. GetKeyHistory separately reports retired
// keys with off-card certificates; this iterator reads on-card objects only.
func (d *Device) Certificates(ctx context.Context) iter.Seq2[Certificate, error] {
	return func(yield func(Certificate, error) bool) {
		keys := [24]protocol.KeyReference{
			protocol.PIVAuthentication,
			protocol.DigitalSignature,
			protocol.KeyManagement,
			protocol.CardAuthentication,
		}
		for i := 4; i < len(keys); i++ {
			keys[i] = protocol.RetiredKey1 + protocol.KeyReference(i-4)
		}

		for _, key := range keys {
			der, err := d.GetCertificateDER(ctx, key)
			entry := Certificate{Key: key, DER: der}

			stop := err != nil && !certificateReadCanContinue(err)
			if err == nil {
				entry.Certificate, err = x509.ParseCertificate(der)
				if err != nil {
					err = fmt.Errorf("%w: certificate DER: %v", protocol.ErrInvalidResponse, err)
				}
			}

			if !yield(entry, err) || stop {
				return
			}
		}
	}
}

// Only complete APDU rejections and local object parsing failures leave the
// connection available for the next slot. An invalidated transport can wrap
// ErrInvalidResponse, so terminal causes take precedence over parsing errors.
func certificateReadCanContinue(err error) bool {
	var invalidated *transport.DeviceInvalidatedError

	var ioErr *transport.IOError
	if errors.As(err, &invalidated) || errors.As(err, &ioErr) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, io.ErrClosedPipe) {
		return false
	}

	var apdu *iso7816.APDUError

	return errors.As(err, &apdu) || errors.Is(err, protocol.ErrInvalidResponse)
}
