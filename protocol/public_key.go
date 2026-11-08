package protocol

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/telesma-app/bertlv"
)

// ParsePublicKey parses a GENERATE ASYMMETRIC KEY PAIR response (tag 0x7f49).
// The key must match the requested algorithm. The result is an *rsa.PublicKey
// or an *ecdsa.PublicKey. RSA public exponents must fit the positive 31-bit
// range supported by crypto/rsa, a subset of the PIV exponent range.
func ParsePublicKey(algorithm Algorithm, data []byte) (crypto.PublicKey, error) {
	var (
		bits  int
		curve elliptic.Curve
	)

	switch algorithm {
	case RSA1024:
		bits = 1024
	case RSA2048:
		bits = 2048
	case RSA3072:
		bits = 3072
	case ECCP256:
		curve = elliptic.P256()
	case ECCP384:
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("piv: unsupported public key algorithm %02x", byte(algorithm))
	}

	data, err := ParseObject(data, 0x7f49)
	if err != nil {
		return nil, err
	}

	var modulus, exponent, point []byte

	for len(data) > 0 {
		tag, value, rest, err := bertlv.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
		}

		data = rest

		var field *[]byte

		switch tag {
		case 0x81:
			field = &modulus
		case 0x82:
			field = &exponent
		case 0x86:
			field = &point
		default:
			return nil, fmt.Errorf("%w: unexpected public key tag %x", ErrInvalidResponse, tag)
		}

		if *field != nil {
			return nil, fmt.Errorf("%w: duplicate public key tag %x", ErrInvalidResponse, tag)
		}

		*field = value
	}

	if curve != nil {
		if modulus != nil || exponent != nil {
			return nil, fmt.Errorf("%w: RSA parameters for an ECC key", ErrInvalidResponse)
		}

		key, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("%w: ECC public key: %v", ErrInvalidResponse, err)
		}

		return key, nil
	}

	// Exponents are unsigned integers. Apply crypto/rsa's range to the value,
	// independently of leading zero octets in its wire representation.
	for len(exponent) != 0 && exponent[0] == 0 {
		exponent = exponent[1:]
	}

	if point != nil || len(modulus) != bits/8 || len(exponent) == 0 || len(exponent) > 4 {
		return nil, fmt.Errorf("%w: invalid RSA public key parameters", ErrInvalidResponse)
	}

	n := new(big.Int).SetBytes(modulus)
	if n.BitLen() != bits || n.Bit(0) == 0 {
		return nil, fmt.Errorf("%w: invalid RSA modulus", ErrInvalidResponse)
	}

	var e uint32
	for _, b := range exponent {
		e = e<<8 | uint32(b)
	}
	// crypto/rsa limits public exponents to positive 31-bit integers.
	if e < 3 || e > 1<<31-1 || e&1 == 0 {
		return nil, fmt.Errorf("%w: invalid RSA public exponent", ErrInvalidResponse)
	}

	return &rsa.PublicKey{N: n, E: int(e)}, nil
}
