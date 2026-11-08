package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

func main() {
	reader := flag.String("reader", "", "exact PC/SC reader name (required)")
	slot := flag.String("slot", "9d", "key-management slot in hex: 9d or 82..95")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for the complete key agreement")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if err := run(ctx, *reader, *slot, os.Getenv("PIV_PIN")); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, reader, slot, pin string) (err error) {
	if reader == "" {
		return errors.New("-reader is required")
	}

	value, err := strconv.ParseUint(slot, 16, 8)
	if err != nil {
		return fmt.Errorf("parse -slot: %w", err)
	}

	reference := protocol.KeyReference(value)
	if reference != protocol.KeyManagement && (reference < protocol.RetiredKey1 || reference > protocol.RetiredKey20) {
		return fmt.Errorf("unsupported ECDH slot %02x: use 9d or 82..95", reference)
	}

	if pin == "" {
		return errors.New("PIV_PIN is required")
	}

	connection, err := pivpcsc.Open(ctx, reader)
	if err != nil {
		return err
	}

	device := card.New(connection)
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	certificate, err := device.GetCertificate(ctx, reference)
	if err != nil {
		return err
	}

	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("slot %02x requires a P-256 or P-384 key, got %T", reference, certificate.PublicKey)
	}

	key, err := device.PrivateKey(reference, publicKey)
	if err != nil {
		return err
	}

	cardPublic, err := publicKey.ECDH()
	if err != nil {
		return err
	}

	// A local ephemeral peer makes this a self-contained demonstration.
	peer, err := cardPublic.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	authentication := card.PINAuthentication(protocol.ApplicationPIN, func(context.Context) (string, error) {
		return pin, nil
	})

	secret, err := key.ECDH(ctx, peer.PublicKey(), authentication)
	if err != nil {
		return err
	}
	defer clear(secret)

	peerSecret, err := peer.ECDH(cardPublic)
	if err != nil {
		return err
	}
	defer clear(peerSecret)

	if subtle.ConstantTimeCompare(secret, peerSecret) != 1 {
		return errors.New("card and peer shared secrets do not match")
	}

	// Apply a KDF instead of using the raw ECDH output as an application key.
	// A real protocol also authenticates peers and binds its transcript in info.
	derived, err := hkdf.Key(sha256.New, secret, nil, "github.com/telesma-app/piv/examples/ecdh", 32)
	if err != nil {
		return err
	}
	defer clear(derived)

	_, err = fmt.Printf("%s ECDH agreement verified; derived %d bytes with HKDF-SHA-256\n", publicKey.Curve.Params().Name, len(derived))

	return err
}
