package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	pivpcsc "github.com/telesma-app/piv/backend/pcsc"
	"github.com/telesma-app/piv/card"
	"github.com/telesma-app/piv/protocol"
)

func main() {
	reader := flag.String("reader", "", "exact PC/SC reader name (required)")
	timeout := flag.Duration("timeout", 30*time.Second, "timeout for the complete round trip")

	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	if err := run(ctx, *reader, os.Getenv("PIV_PIN")); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, reader, pin string) (err error) {
	if reader == "" {
		return errors.New("-reader is required")
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

	certificate, err := device.GetCertificate(ctx, protocol.KeyManagement)
	if err != nil {
		return err
	}

	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("slot 9d requires an RSA key, got %T", certificate.PublicKey)
	}

	key, err := device.PrivateKey(protocol.KeyManagement, publicKey)
	if err != nil {
		return err
	}

	message := []byte("PIV RSA-OAEP round trip")
	label := []byte("github.com/telesma-app/piv/examples/rsa-oaep")

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, label)
	if err != nil {
		return err
	}

	// VERIFY and decryption run as one card operation. No PIN retry is attempted.
	authentication := card.PINAuthentication(protocol.ApplicationPIN, func(context.Context) (string, error) {
		return pin, nil
	})
	decrypter := key.Decrypter(ctx, authentication)

	// Hash and label must match the encryption parameters.
	plaintext, err := decrypter.Decrypt(rand.Reader, ciphertext, &rsa.OAEPOptions{
		Hash: crypto.SHA256, Label: label,
	})
	if err != nil {
		return err
	}
	defer clear(plaintext)

	if !bytes.Equal(plaintext, message) {
		return errors.New("decrypted message does not match the original")
	}

	_, err = fmt.Printf("RSA-%d OAEP/SHA-256 round trip verified (%d plaintext bytes)\n", publicKey.N.BitLen(), len(plaintext))

	return err
}
