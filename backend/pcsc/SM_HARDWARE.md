# TOKEN2 R3.4 NIST PIV Secure Messaging verification

Date: 2026-11-07. Host: macOS, Go 1.27.3, USB CCID through PC/SC.
Reader: `TOKEN2 FIDO2 Security Key(0024)`.
Application label: `Token2 R3.4`.

Result: **PASS**, CS7 (`2E`), separately with short and extended protected APDUs.
Each run opened a fresh exclusive connection with reset on close. Handshake
APDUs used short encoding in both runs. SELECT advertised `2E`.

Trust used the independently obtained vendor `TOKEN2 PIV CA` from the previous
interoperability investigation, at
`/private/tmp/token2-r34/sources/token2-piv-ca.pem`. The card-provided X.509
content signer was validated against that CA, including its content-signing
EKU and digitalSignature usage. The signed P-384 CVC and the key-confirmation
cryptogram were verified before the session became available.

| Certificate | SHA-256 of DER |
| --- | --- |
| Trusted TOKEN2 PIV CA | `8e037ded101c42f1e33a68a1ec96042e6764fc18a647b91158c4d01d15b307c6` |
| Card content signer | `d0d6f46444df4f1ab6873320acaa4367da197c3305d2c2616cb089f4ad13e461` |

In each session, two rounds of the following protected reads matched the
plaintext baseline byte for byte:

| Object | Content bytes returned by `GetData` |
| --- | ---: |
| Discovery (`7E`) | 18 |
| Card Capability Container (`5FC107`) | 27 |
| CHUID (`5FC102`) | 59 |
| Secure Messaging Certificate Signer (`5FC122`) | 541 |

This verified eight sequential authenticated exchanges per session. The short
run used 12 framing GET RESPONSE commands during those exchanges, all with CLA
`00`. The extended run returned the protected responses without GET RESPONSE.

The original run used the local development workspace. Reproduction uses
the dependencies in `go.mod` and independently trusted CA material:

```sh
PIV_SM_TEST=1 \
PIV_READER='TOKEN2 FIDO2 Security Key(0024)' \
PIV_SM_CA_FILE=/path/to/trusted-token2-piv-ca.pem \
GOWORK=off go test -v ./backend/pcsc -run TestSMHardware -count=1
```

`PIV_SM_INTERMEDIATE_FILE` optionally supplies X.509 intermediate certificates.
The harness is [`sm_hardware_test.go`](sm_hardware_test.go). It performs SELECT,
public GET DATA and ephemeral key establishment only. It never submits a PIN
or pairing code, signs, generates keys, writes certificates or changes persistent
configuration. Connection close resets temporary session state.

NFC/VCI, pairing, private-key use, authenticated application errors, optional
intermediate CVCs and outgoing command chaining were not exercised on hardware.
CS2 was not exercised on hardware; the harness explicitly requests CS7.
These paths have scripted or cryptographic tests. In particular, the framing
test sends a 626-byte protected command in three fragments and authenticates a
723-byte response collected through plaintext GET RESPONSE, then checks the
next exchange's counter and both MAC chains using independent vectors.

These results apply to this physical token. They complement the previous
SCP11b investigation in `/private/tmp/iso7816-scp11-interop/RESULTS.txt`: that
profile's initialization returned `6D00` on this token, while NIST CS7 succeeds.
