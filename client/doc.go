// Package client sends PIV commands through a borrowed APDU transport.
// The caller owns the transport and serializes workflows that depend on PIN
// verification or multi-step administration authentication.
package client
