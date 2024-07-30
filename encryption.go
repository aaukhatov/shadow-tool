package shadowflow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

type EncryptionService interface {
	Encrypt(plainText string) (string, error)
}

// NoopEncryptionService is a version of the EncryptionService that doesn't perform any encryption,
// it only encodes the differences as a base64 string as defined in RFC 4648.
type NoopEncryptionService struct {
}

func (e *NoopEncryptionService) Encrypt(plainText string) (string, error) {
	if plainText == "" {
		return "", errors.New("plainText cannot be empty")
	}
	return base64.StdEncoding.EncodeToString([]byte(plainText)), nil
}

func NewNoopEncryptionService() *NoopEncryptionService {
	return &NoopEncryptionService{}
}

// PublicKeyEncryptionService is a struct that represents the EncryptionService for encrypting data using a public key.
// The encryption process uses SHA-256 as the hash function.
type PublicKeyEncryptionService struct {
	publicKey *rsa.PublicKey
}

func NewPublicKeyEncryptionService(publicKey *rsa.PublicKey) *PublicKeyEncryptionService {
	return &PublicKeyEncryptionService{publicKey: publicKey}
}

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
