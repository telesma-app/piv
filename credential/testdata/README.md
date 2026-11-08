# RSA-PSS interoperability fixtures

Generated with OpenSSL 3.5.9. The synthetic 2048-bit RSA private key was created
only for these fixtures and discarded. `pss-public-key.pem` is its public key;
`pss-message.txt` is the signed message. Each `pss-sha256-saltN.sig` is a binary
RSA-PSS signature with SHA-256, MGF1/SHA-256, and exactly N salt bytes.

Generation and independent verification used:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
openssl pkey -in key.pem -pubout -out pss-public-key.pem
openssl dgst -sha256 -sign key.pem -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:N -out pss-sha256-saltN.sig pss-message.txt
openssl dgst -sha256 -verify pss-public-key.pem -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:N -signature pss-sha256-saltN.sig pss-message.txt
```

The empty-salt fixture checks the CMS meaning of salt length zero independently
of Go's `crypto/rsa` convention, where `PSSOptions.SaltLength == 0` requests
automatic detection. The other fixtures distinguish exactly empty, default
20-byte, and hash-sized salts.
