# telesma-app/piv

Go library for PIV smart cards over ISO 7816 and PC/SC, using
[`telesma-app/iso7816`](https://github.com/telesma-app/iso7816) and
[`telesma-app/pcsc`](https://github.com/telesma-app/pcsc). It provides low-level
PIV commands and a card API for common workflows.

> [!WARNING]
> This module is under active development. Its public API may change during `v0.x`.

## Support

- typed CHUID, CCC, Printed Information, Discovery and Key History;
- Discovery/Key History encoding and off-card certificate file parsing;
- X.509 certificate reading and DER export from all 24 standard slots;
- PIN status, verification, change and unblock;
- RSA PKCS#1 v1.5/PSS and ECDSA signing, including a `crypto.Signer` adapter;
- RSA OAEP/PKCS#1 v1.5 decryption, including a `crypto.Decrypter` adapter;
- P-256/P-384 ECDH with key-management and retired keys;
- key generation and certificate installation with administration authentication;
- NIST PIV Secure Messaging CS2/CS7 and GlobalPlatform SCP11b channels.

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
	ctx := context.Background()

	connection, err := pivpcsc.Open(ctx, "exact PC/SC reader name")
	if err != nil {
		log.Fatal(err)
	}

	device := card.New(connection)
	defer device.Close()

	certificate, err := device.GetCertificate(ctx, protocol.DigitalSignature)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(certificate.PublicKeyAlgorithm)
}
```

`pivpcsc.Open` opens an exclusive connection and selects PIV. `card.New` takes
ownership of it; `device.Close` closes the connection and resets the card.
The initial SELECT result is available through `device.ApplicationProperties()`
without another card command.

Use `Certificates(ctx)` to iterate over all standard slots, or
`GetCertificateDER` to export a certificate without X.509 parsing.
Reading a certificate does not establish trust or prove that its private key
is present.

## API levels

The data models follow NIST SP 800-73-5 Part 1, and `client.Client` exposes the
card commands from Part 2. `card.Device` adds Go workflows for authentication,
private-key operations and administration. Part 3 defines a separate, optional
PIV middleware API.

| Package | Use it for |
| --- | --- |
| [`card`](card) | Card sessions, certificates, PINs, private-key operations and administration |
| [`client`](client) | Individual PIV commands over a borrowed transport |
| [`backend/pcsc`](backend/pcsc) | Finding readers and opening PIV connections |
| [`transport/iso7816`](transport/iso7816) | APDU exchanges, command chaining and response collection |
| [`transport/sm`](transport/sm) | NIST PIV CS2/CS7 secure messaging |
| [`protocol`](protocol) | PIV constants, object encodings and response parsing |

`card.Device` serializes complete operations and does not retain PINs or
administration keys. `client.Client` leaves connection ownership and workflow
serialization to the caller. See the package documentation for method contracts.

Vendor PIV adapters are under development in the separate
[`telesma-app/yubico`](https://github.com/telesma-app/yubico) and
[`telesma-app/token2`](https://github.com/telesma-app/token2) modules and will be
released independently. This module has no dependency on either vendor module.

`Device.ExchangeAdministration` authenticates an explicit management key,
optionally verifies an `AuthenticationSource`, and sends a vendor APDU under
one operation gate. It returns the final status word without interpretation,
as `Exchange` does. Vendor packages encode their commands and interpret their
responses; they do not choose default credentials or retry persistent writes.

| Part 2 command | `client.Client` method | Scope |
| --- | --- | --- |
| SELECT | `Select` | Selects PIV using its nine-byte AID prefix |
| GET DATA | `GetData` | Returns object contents without the outer template |
| VERIFY | `Verify` | Encoded reference data, status queries and security-status resets |
| CHANGE REFERENCE DATA | `ChangeReferenceData` | Current and replacement PIN/PUK values, each eight encoded bytes |
| RESET RETRY COUNTER | `ResetRetryCounter` | Eight-byte PUK and replacement application PIN |
| GENERAL AUTHENTICATE | `GeneralAuthenticate` | Dynamic authentication template; caller supplies hashing, padding and verification |
| PUT DATA | `PutData` | Replaces object contents after administration authentication |
| GENERATE ASYMMETRIC KEY PAIR | `GenerateAsymmetricKeyPair` | Replaces a private key and returns its public key after administration authentication |

`ChangeReferenceData` implements the standard PIN/PUK form. Optional card
management extensions for other references, such as OCC data, require raw APDU
commands. `VerifyPIN`, `GetCertificate` and the typed object reads are convenience
methods over these commands.

`ReferenceStatus(ctx, reference)` queries a reference, including a PIN or OCC,
without submitting authentication data or consuming a retry. It returns exact
retry counts from `63Cx`; `6983` remains an APDU error without an inferred count.
Failed reference-data commands report `63Cx` through `client.ReferenceDataError`,
which preserves the reference, retry count and APDU status.

## Application metadata and data objects

```go
application, available := device.ApplicationProperties()
if available {
	fmt.Println(application.ApplicationLabel, application.Algorithms)
}
```

This is the snapshot obtained when the connection was selected, with AID, tag
allocation authority AID, label, URL and advertised algorithms. Unknown algorithm
identifiers are retained. The slices are read-only, and the snapshot remains
available after `Close`; it does not report current authentication or key state.
`card.New` obtains it from ISO 7816 and NIST secure-messaging transports.

For an external wrapper such as SCP11, retain `connection.ApplicationProperties()`
before transferring the connection to the wrapper, then use
`card.NewWithApplicationProperties(channel, application)`. This constructor
copies the supplied metadata slices. Without a provider or explicit snapshot,
`device.ApplicationProperties()` returns `available == false`.

Typed reads are available on both `card.Device` and `client.Client`:

| Method | Result |
| --- | --- |
| `GetCHUID(ctx)` | `protocol.CHUID`: FASC-N, GUID, expiration date, optional cardholder UUID and issuer signature |
| `GetCCC(ctx)` | `protocol.CCC`: card identifier, GSC-IS versions and data-model fields |
| `GetPrintedInformation(ctx)` | `protocol.PrintedInfo`: cardholder text and printed expiration date |
| `GetDiscovery(ctx)` | `protocol.Discovery`: AID and PIN Usage Policy |
| `GetKeyHistory(ctx)` | `protocol.KeyHistory`: retired-key counts and off-card certificate URL |

Reads are not cached. Missing objects remain APDU errors (`6A82`), and malformed
objects match `protocol.ErrInvalidResponse`. `ParseCHUID`, `ParseCCC` and
`ParsePrintedInformation` also accept object contents returned by `GetData`.
CHUID and CCC preserve the original object bytes in `Raw`; those views borrow
the input. Parsing does not verify signatures or establish trust. Dates are
calendar dates at midnight UTC; expiry policy belongs to the application.

`protocol.EncodeDiscovery` and `protocol.EncodeKeyHistory` encode the supplied
model for `PutData`, without the outer `7E` or `53` template. They preserve
supplied values without choosing a PIN policy, normalizing a URL or validating
the caller's data. Administrative writes take an explicit `card.AdministrationKey`.

`protocol.ParseOffCardKeyHistoryFile(fileDER)` returns ordered
`protocol.OffCardCertificate` entries containing a retired key reference and
borrowed certificate DER. It checks the file schema independently of Go's X.509
parser. Fetching the file, checking its URL's SHA-256 hash and verifying
certificates belong to the application. Security Object and biometric objects
remain available as raw values through `GetData`.

## Private-key operations

Bind a slot using `device.PrivateKey(reference, publicKey)`. Public keys from a
matching certificate or `GenerateAsymmetricKeyPair` are suitable. For ECC,
use the `*ecdsa.PublicKey` returned by certificate parsing or generation.

Each operation accepts an explicit context and optional `AuthenticationSource`.
`card.PINAuthentication(protocol.ApplicationPIN, requestPIN)` obtains a PIN for
each operation, where `requestPIN` is the application's
`func(context.Context) (string, error)`. The authentication source runs outside
the operation gate; VERIFY and the private-key command run together under it.

For an RSA key, decrypt OAEP ciphertext with explicit options:

```go
plaintext, err := key.Decrypt(ctx, rand.Reader, ciphertext, &rsa.OAEPOptions{
	Hash: crypto.SHA256,
}, authentication)
```

The imports are `crypto`, `crypto/rand` and `crypto/rsa`. The ciphertext must
contain exactly the RSA modulus width in bytes. OAEP honors `Hash`, `MGFHash`
and `Label`. A zero `MGFHash` uses `Hash`. Nil options select legacy PKCS#1 v1.5;
`&rsa.PKCS1v15DecryptOptions{SessionKeyLen: n}` returns a random `n`-byte key on
invalid padding or a different plaintext length. The enclosing protocol must
not reveal whether the real or random key was used. New protocols should use OAEP.
`key.Decrypter(ctx, authentication)` adapts the same operation to `crypto.Decrypter`.

For a P-256/P-384 key in slot `9D` or `82` through `95`, pass a peer public key
from `crypto/ecdh` on the same curve:

```go
secret, err := key.ECDH(ctx, peerPublicKey, authentication)
```

The result is the raw big-endian shared secret, exactly 32 or 48 bytes including
leading zeros. Apply the KDF required by the application's protocol. Plaintext
and shared-secret buffers belong to the caller. These operations do not prove
that the card's key still matches the bound public key.

## Secure channels

Establish a secure channel before passing it to `card.New`:

- [`transport/sm`](transport/sm) provides NIST PIV CS2/CS7 using a trusted content
  signer. Pairing and VCI checks are explicit card operations.
- [`iso7816/scp11`](https://github.com/telesma-app/iso7816/tree/master/scp11)
  provides GlobalPlatform SCP11b using a trusted static card key.

Supply independently trusted keys or CA certificates. A certificate retrieved
from the card alone does not establish trust. CS2/CS7 protect GET DATA, VERIFY,
CHANGE REFERENCE DATA and GENERAL AUTHENTICATE; administrative writes and key
generation require another suitable transport.

Select the NIST cipher suite explicitly when opening a channel:

```go
channel, err := sm.Open(ctx, connection, sm.Parameters{
	Trust:       trust,
	CipherSuite: protocol.CipherSuite7,
	Encoding:    iso7816.EncodingShort,
})
```

Use `protocol.CipherSuite2` for P-256/AES-128 or `protocol.CipherSuite7` for
P-384/AES-256. The card must advertise the requested suite. `CipherSuite` has no
default. The imports are `github.com/telesma-app/piv/transport/sm` and
`github.com/telesma-app/iso7816`, alongside `protocol`.

Both channels close on unauthenticated responses. Some firmware returns
unsigned errors for absent objects, which can stop certificate enumeration
over SCP11b.

## Inspection example

[`examples/inspect`](examples/inspect) lists inserted PIV cards, queries PIN
status and reads certificate metadata without submitting a PIN or writing data:

```sh
go run ./examples/inspect
go run ./examples/inspect -reader 'exact PC/SC reader name' -timeout 30s
```

## Testing

```sh
go test ./...
go vet ./...
go test -race ./...
make lint
```

The normal suite does not require hardware. The read-only hardware test is opt-in:

```sh
PIV_TEST=1 PIV_READER='exact PC/SC reader name' go test -v ./backend/pcsc -run TestPIVHardware -count=1
```

USB reads were tested on TOKEN2 R3.4 and YubiKey; CS7 was tested on TOKEN2 R3.4
and SCP11b on YubiKey 5.7.4. See the [CS7 hardware report](backend/pcsc/SM_HARDWARE.md)
for reproduction and limits. CS2, PIN submission, signing, decryption, application
ECDH, persistent writes and NFC have not been tested on hardware.

## License

[Apache License 2.0](LICENSE).

## References

- [NIST SP 800-73-5 Part 1: PIV data model](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt1-5.pdf)
- [NIST SP 800-73-5 Part 2: PIV command interface](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt2-5.pdf)
- [NIST SP 800-73-5 Part 3: PIV middleware API](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73pt3-5.pdf)
