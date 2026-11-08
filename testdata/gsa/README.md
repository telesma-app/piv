# Public GSA PIV test objects

These unchanged binary fixtures come from the U.S. General Services
Administration's [ICAM Card Builder](https://github.com/GSA/gsa-icam-card-builder),
commit `6d5a872547b96c48dff7fc7c14ae1d205438ae38`, directory
[`cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV`](https://github.com/GSA/gsa-icam-card-builder/tree/6d5a872547b96c48dff7fc7c14ae1d205438ae38/cards/ICAM_Card_Objects/46_Golden_FIPS_201-2_PIV).

They are published test credentials and biometric samples, not user card data.
They provide an independent interoperability oracle for PIV object formats,
detached CMS signatures, and Security Object digests. Their historical
certificates are verified at an explicit test time; they are never production
trust anchors.

| Local file | Original filename |
| --- | --- |
| `card46-discovery.bin` | `1 - Discovery Object` |
| `card46-security-object.bin` | `2 - Security Object` |
| `card46-ccc.bin` | `7 - CCC` |
| `card46-chuid.bin` | `8 - CHUID Object` |
| `card46-fingerprints.bin` | `9 - Fingerprints` |
| `card46-face.bin` | `10 - Face Object` |
| `card46-printed-information.bin` | `11 - Printed Information` |
| `card46-signer.bin` | `CHUID_Signer.crt` (PEM despite the local suffix) |

The files contain object contents without GET DATA's outer `53`, `7E`, or
`7F61` template. The signer file is a PEM certificate.
