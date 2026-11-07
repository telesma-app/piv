package card

import (
	"context"
	"crypto/x509"

	"github.com/telesma-app/piv/client"
	"github.com/telesma-app/piv/protocol"
)

// GetData reads a PIV object without its outer template. An absent object is
// reported as an iso7816.APDUError with status 6A82.
func (d *Device) GetData(ctx context.Context, object protocol.Object) ([]byte, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	data, err := d.client.GetData(ctx, object)

	return data, d.operationError(err)
}

// GetCertificateDER reads and decompresses a slot's certificate without parsing
// or validating its DER contents. It can export certificates unsupported by the
// X.509 parser.
func (d *Device) GetCertificateDER(ctx context.Context, key protocol.KeyReference) ([]byte, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	der, err := d.client.GetCertificateDER(ctx, key)

	return der, d.operationError(err)
}

// GetCertificate reads a slot's X.509 certificate. Parsing does not verify its
// signature or establish trust.
func (d *Device) GetCertificate(ctx context.Context, key protocol.KeyReference) (*x509.Certificate, error) {
	if err := d.lock(ctx); err != nil {
		return nil, err
	}
	defer d.unlock()

	certificate, err := d.client.GetCertificate(ctx, key)

	return certificate, d.operationError(err)
}

// GetKeyHistory reads the retired-key counts and off-card certificate location.
// An absent optional object is an iso7816.APDUError with status 6A82, distinct
// from a present history with zero counts. It does not fetch off-card data.
func (d *Device) GetKeyHistory(ctx context.Context) (protocol.KeyHistory, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.KeyHistory{}, err
	}
	defer d.unlock()

	history, err := d.client.GetKeyHistory(ctx)

	return history, d.operationError(err)
}

// GetDiscovery reads the optional Discovery Object and its PIN Usage Policy.
// Absence remains an iso7816.APDUError (6A82), and the policy does not select an
// authentication method or establish a VCI.
func (d *Device) GetDiscovery(ctx context.Context) (protocol.Discovery, error) {
	if err := d.lock(ctx); err != nil {
		return protocol.Discovery{}, err
	}
	defer d.unlock()

	discovery, err := d.client.GetDiscovery(ctx)

	return discovery, d.operationError(err)
}

// ReferenceStatus queries a reference's security status without submitting
// authentication data or consuming a retry.
func (d *Device) ReferenceStatus(ctx context.Context, reference protocol.KeyReference) (client.ReferenceStatus, error) {
	if err := d.lock(ctx); err != nil {
		return client.ReferenceStatus{}, err
	}
	defer d.unlock()

	status, err := d.client.ReferenceStatus(ctx, reference)

	return status, d.operationError(err)
}
