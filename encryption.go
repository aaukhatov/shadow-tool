// Package shadowflow runs a new code path alongside an existing one on a
// sample of traffic, diffs their results, and logs the differences —
// optionally encrypting the logged values to avoid leaking sensitive data.
package shadowflow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// EncryptionService encrypts the diff values logged by a ShadowFlow so they
// don't leak sensitive data in plain text.
type EncryptionService interface {
	Encrypt(plainText string) (string, error)
}

// KeyFingerprinter is implemented by EncryptionService implementations that
// have an associated key, so a ShadowFlow can log which key encrypted a
// value. This lets old log lines be matched to the right private key after
// key rotation.
type KeyFingerprinter interface {
	KeyFingerprint() string
}

// NoopEncryptionService is a version of the EncryptionService that doesn't perform any encryption,
// it only encodes the differences as a base64 string as defined in RFC 4648.
type NoopEncryptionService struct{}

// Encrypt base64-encodes plainText without performing any real encryption.
func (e *NoopEncryptionService) Encrypt(plainText string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(plainText)), nil
}

// NewNoopEncryptionService creates a NoopEncryptionService.
func NewNoopEncryptionService() *NoopEncryptionService {
	return &NoopEncryptionService{}
}

// PublicKeyEncryptionService is a struct that represents the EncryptionService for encrypting data using a public key.
// The encryption process uses SHA-256 as the hash function.
type PublicKeyEncryptionService struct {
	publicKey      *rsa.PublicKey
	keyFingerprint string
}

// NewPublicKeyEncryptionService creates a PublicKeyEncryptionService that
// encrypts with the given RSA public key. The key must be at least 2048 bits;
// smaller RSA keys provide inadequate encryption strength.
func NewPublicKeyEncryptionService(publicKey *rsa.PublicKey) (*PublicKeyEncryptionService, error) {
	if publicKey == nil {
		return nil, errors.New("public key cannot be nil")
	}
	if bits := publicKey.N.BitLen(); bits < 2048 {
		return nil, fmt.Errorf("public key must be at least 2048 bits, got %d", bits)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	sum := sha256.Sum256(derBytes)

	return &PublicKeyEncryptionService{
		publicKey:      publicKey,
		keyFingerprint: hex.EncodeToString(sum[:8]),
	}, nil
}

// KeyFingerprint returns a short, stable identifier for the configured public
// key (the first 8 bytes of the SHA-256 hash of its DER encoding), so log
// lines can be matched to the private key that can decrypt them.
func (e *PublicKeyEncryptionService) KeyFingerprint() string {
	return e.keyFingerprint
}

// Encrypt encrypts plainText with RSA-OAEP using the configured public key
// and returns the result base64-encoded.
func (e *PublicKeyEncryptionService) Encrypt(plainText string) (string, error) {
	encryptedData, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		e.publicKey,
		[]byte(plainText),
		nil,
	)

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedData), nil
}
