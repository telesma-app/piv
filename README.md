# telesma-app/piv

[![Go Reference](https://pkg.go.dev/badge/github.com/telesma-app/piv.svg)](https://pkg.go.dev/github.com/telesma-app/piv)
[![Go](https://github.com/telesma-app/piv/actions/workflows/go.yml/badge.svg)](https://github.com/telesma-app/piv/actions/workflows/go.yml)

Go library for PIV smart cards. It provides low-level PIV commands and card
workflows over [ISO 7816](https://github.com/telesma-app/iso7816) and
[PC/SC](https://github.com/telesma-app/pcsc).

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Support

- Card metadata, Discovery and Key History.
- X.509 certificate reading and DER export from all 24 standard slots.
- PIN status, verification, change and unblock.
- RSA and ECDSA signing, RSA decryption and ECDH, with Go crypto adapters.
- Key generation and certificate installation with administration authentication.
- NIST PIV CS2/CS7 secure messaging and GlobalPlatform SCP11b channels.

Available operations depend on the card and its access policy.

## Installation

```sh
go get github.com/telesma-app/piv@v0.1.0
```

See [`go.mod`](go.mod) for the required Go version.

## Quick start

Open a reader by its exact PC/SC name and read a certificate:

```go
package main

import (
	"context"
	"fmt"
	"log"

	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx := context.Background()

	connection, err := pivpcsc.Open(ctx, "exact PC/SC reader name")
	if err != nil {
		return err
	}

	device := card.New(connection)
	defer device.Close()

	certificate, err := device.GetCertificate(ctx, protocol.DigitalSignature)
	if err != nil {
		return err
	}

	fmt.Println(certificate.PublicKeyAlgorithm)
	return nil
}
```

`Open` selects PIV using an exclusive connection. `card.New` takes ownership
of it; closing the device resets the card. Use `Certificates(ctx)` to enumerate
slots or `GetCertificateDER` to export bytes without X.509 parsing.
Reading a certificate does not establish trust.

## Packages

| Package | Purpose |
| --- | --- |
| [`card`](card) | Card sessions, certificates, PINs and private-key workflows |
| [`client`](client) | Individual PIV commands over a borrowed transport |
| [`backend/pcsc`](backend/pcsc) | Reader discovery and PIV connections |
| [`transport/iso7816`](transport/iso7816) | APDU exchanges, chaining and response collection |
| [`transport/sm`](transport/sm) | NIST PIV CS2/CS7 secure messaging |
| [`protocol`](protocol) | PIV constants, data models and encodings |

Secure channels are established before `card.New` and require independently
trusted keys or CA certificates. SCP11b is provided by
[`iso7816/scp11`](https://github.com/telesma-app/iso7816/tree/master/scp11).

## Vendor extensions

Vendor-specific PIV commands are available in
[`yubico/piv`](https://github.com/telesma-app/yubico/tree/master/piv) and
[`token2/piv`](https://github.com/telesma-app/token2/tree/master/piv): slot metadata,
attestation, key import and generation with PIN/touch policies, and vendor
administration commands.

Add the corresponding vendor module to your application and pass the existing
`*card.Device` to its functions. Supported commands depend on the device and firmware.

## Examples

[`examples/inspect`](examples/inspect) lists inserted PIV cards, queries PIN
status and reads certificate metadata without submitting a PIN or writing data:

```sh
go run ./examples/inspect
go run ./examples/inspect -reader 'exact PC/SC reader name'
```

Additional runnable examples cover the main private-key and secure-channel workflows:

| Example | Workflow |
| --- | --- |
| [`csr`](examples/csr) | Create a PEM certificate request with an existing slot key through `crypto.Signer` |
| [`rsa-oaep`](examples/rsa-oaep) | Encrypt locally and decrypt on the card through `crypto.Decrypter` |
| [`ecdh`](examples/ecdh) | Agree a secret with a local ephemeral peer and derive a key with HKDF |
| [`secure-messaging`](examples/secure-messaging) | Validate card trust, establish NIST CS7 and read a protected object |

See [`examples/README.md`](examples/README.md) for prerequisites and commands.

## Development

```sh
go test ./...
go vet ./...
make lint
```

The normal test suite does not require hardware.

## License

[Apache License 2.0](LICENSE).

## References

- [NIST SP 800-73-5 Part 1: PIV data model](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf)
- [NIST SP 800-73-5 Part 2: PIV command interface](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt2-5.pdf)
- [PIV Secure Messaging (CS2/CS7): NIST SP 800-73-5 Part 2, Section 4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt2-5.pdf#page=33)
