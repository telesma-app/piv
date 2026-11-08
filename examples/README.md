# PIV examples

Run these commands from the repository root with a PC/SC service and an inserted
PIV card. Use `inspect` to find the exact reader name:

```sh
go run ./examples/inspect
```

All examples support `-timeout` (default `30s`) and cancellation with Ctrl-C.
Connections are exclusive and reset the card when closed. Available algorithms
and operations depend on the card and its access policy.

## Certificate request

`csr` adapts the existing digital-signature key in slot **9c** to `crypto.Signer`
and passes it to `x509.CreateCertificateRequest`. The matching certificate must
already be installed in the slot so the example can read its public key.
Supported keys are RSA-1024/2048/3072 and ECDSA P-256/P-384.

Set the `PIV_PIN` environment variable to your application PIN, then run:

```sh
go run ./examples/csr -reader 'exact PC/SC reader name' -cn 'PIV example' > request.pem
```

The output is a PEM certificate request with the supplied subject common name.
The example uses the existing key and does not generate a key or install a
certificate. Add any subject alternative names required by your issuing CA to
the `x509.CertificateRequest` template.

## RSA-OAEP decryption

`rsa-oaep` reads the RSA certificate in key-management slot **9d**, encrypts a
sample message locally with OAEP/SHA-256, then decrypts it on the card through
`crypto.Decrypter`. It checks that the recovered message matches the original.
The OAEP hash and label are identical on both sides.

With `PIV_PIN` set:

```sh
go run ./examples/rsa-oaep -reader 'exact PC/SC reader name'
```

This requires an existing RSA-1024/2048/3072 key and matching certificate in 9d.
The example prints the round-trip result and plaintext length.

## ECDH key agreement

`ecdh` requires an existing P-256 or P-384 key and matching certificate in
key-management slot **9d** (the default) or a retired slot **82** through **95**.
It creates a local ephemeral software peer, computes both sides of the agreement,
and checks that their shared secrets match. It derives a 32-byte application key
with HKDF-SHA-256 and prints the result without printing secret material.

With `PIV_PIN` set:

```sh
go run ./examples/ecdh -reader 'exact PC/SC reader name'
```

Use `-slot 82` with an EC key in retired slot 82 to keep an RSA key in 9d for the
RSA-OAEP example:

```sh
go run ./examples/ecdh -reader 'exact PC/SC reader name' -slot 82
```

The software peer makes this a local demonstration. An application protocol must
authenticate its peers and bind its protocol context to the derived key.

## NIST secure messaging

`secure-messaging` requires a card supporting **NIST PIV CS7**, its secure-messaging
certificate signer object, and independently trusted content-signing CA
certificates in PEM format. Supply intermediate CA certificates separately when
needed:

```sh
go run ./examples/secure-messaging -reader 'exact PC/SC reader name' \
  -ca trusted-roots.pem -intermediates intermediates.pem
```

Omit `-intermediates` when the signer chains directly to a supplied root.
The example validates the card's content signer, establishes CS7 with short APDU
encoding, and reads the Card Capability Container over the protected connection.
It does not submit a PIN. The CA file must come from a trusted source independent
of the card. A failed handshake returns an error without a plaintext fallback.

## Signed object verification

`verify-objects` verifies a personalized card's CHUID, Security Object and mapped
data-group digests using independently trusted content-signing CA certificates:

```sh
go run ./examples/verify-objects -reader 'exact PC/SC reader name' \
  -ca trusted-roots.pem -intermediates intermediates.pem
```

Set `PIV_PIN` if mapped objects require PIN activation. See the
[`credential` API](https://pkg.go.dev/github.com/telesma-app/piv/credential)
for verification requirements and limits.

## PIN and certificate handling

The three private-key examples submit the application PIN once through
`card.PINAuthentication`, keeping VERIFY and the private-key operation together.
An incorrect PIN can consume a retry; the examples do not retry it. Touch may be
required by the key's policy. They do not change the PIN or replace card objects.

Certificates read from the card provide the bound public key; reading them does
not establish certificate trust. The RSA and ECDH round trips check that the
existing slot key matches that public key. The signer verifies every returned
signature against its bound public key.

The normal `go test ./...` run compiles the examples without opening a reader.
Running them against a card is a separate hardware check.
