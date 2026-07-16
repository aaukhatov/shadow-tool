// Package shadowflow runs a new code path alongside an existing one on a
// sample of traffic, diffs their results, and logs the differences —
// optionally encrypting the logged values to avoid leaking sensitive data.
package shadowflow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// EncryptionService encrypts the diff values logged by a ShadowFlow so they
// don't leak sensitive data in plain text.
type EncryptionService interface {
	Encrypt(plainText string) (string, error)
}

// NoopEncryptionService is a version of the EncryptionService that doesn't perform any encryption,
// it only encodes the differences as a base64 string as defined in RFC 4648.
type NoopEncryptionService struct {
}

// Encrypt base64-encodes plainText without performing any real encryption.
func (e *NoopEncryptionService) Encrypt(plainText string) (string, error) {
	if plainText == "" {
		return "", errors.New("plainText cannot be empty")
	}
	return base64.StdEncoding.EncodeToString([]byte(plainText)), nil
}

// NewNoopEncryptionService creates a NoopEncryptionService.
func NewNoopEncryptionService() *NoopEncryptionService {
	return &NoopEncryptionService{}
}

// PublicKeyEncryptionService is a struct that represents the EncryptionService for encrypting data using a public key.
// The encryption process uses SHA-256 as the hash function.
type PublicKeyEncryptionService struct {
	publicKey *rsa.PublicKey
}

// NewPublicKeyEncryptionService creates a PublicKeyEncryptionService that
// encrypts with the given RSA public key.
func NewPublicKeyEncryptionService(publicKey *rsa.PublicKey) *PublicKeyEncryptionService {
	return &PublicKeyEncryptionService{publicKey: publicKey}
}

// Encrypt encrypts plainText with RSA-OAEP using the configured public key
// and returns the result base64-encoded.
func (encryptionService *PublicKeyEncryptionService) Encrypt(plainText string) (string, error) {
	if plainText == "" {
		return "", errors.New("plainText cannot be empty")
	}

	encryptedData, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		encryptionService.publicKey,
		[]byte(plainText),
		nil,
	)

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(encryptedData), nil
}
