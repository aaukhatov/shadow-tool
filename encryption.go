// Package shadowflow runs a new code path alongside an existing one on a
// sample of traffic, diffs their results, and logs the differences —
// optionally encrypting the logged values to avoid leaking sensitive data.
package shadowflow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// dataKeySize is the size in bytes of the random AES-256 data key generated
// per Encrypt call.
const dataKeySize = 32

// EncryptionService encrypts the diff values logged by a ShadowFlow so they
// don't leak sensitive data in plain text.
type EncryptionService interface {
	Encrypt(plainText string) (string, error)
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

// PublicKeyEncryptionService is a EncryptionService that encrypts data with
// hybrid (envelope) encryption: a random AES-256-GCM data key encrypts the
// payload, and that data key is wrapped with RSA-OAEP (SHA-256) under the
// configured public key. Wrapping only the small data key with RSA, rather
// than the payload itself, removes RSA-OAEP's plaintext size limit (~190
// bytes for a 2048-bit key) and keeps RSA usage small enough that rotating
// the public key later doesn't require re-architecting the payload path.
type PublicKeyEncryptionService struct {
	publicKey *rsa.PublicKey
}

// envelope is the JSON structure returned by Encrypt: the RSA-OAEP-wrapped
// AES data key, the GCM nonce, and the AES-GCM ciphertext, each
// base64-encoded. A holder of the matching private key decrypts by
// RSA-OAEP/SHA-256-decrypting Key to recover the data key, then AES-256-GCM
// opening Ciphertext with Nonce.
type envelope struct {
	Key        string `json:"key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
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
	return &PublicKeyEncryptionService{publicKey: publicKey}, nil
}

// Encrypt hybrid-encrypts plainText: a fresh random AES-256 data key
// encrypts plainText with AES-GCM, and that data key is wrapped with
// RSA-OAEP under the configured public key. Unlike encrypting plainText
// directly with RSA-OAEP, this has no meaningful size limit on plainText.
// The result is a JSON envelope (see envelope) with the wrapped key, nonce,
// and ciphertext, each base64-encoded.
func (e *PublicKeyEncryptionService) Encrypt(plainText string) (string, error) {
	dataKey := make([]byte, dataKeySize)
	if _, err := rand.Read(dataKey); err != nil {
		return "", fmt.Errorf("generate data key: %w", err)
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plainText), nil)

	wrappedKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		e.publicKey,
		dataKey,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("wrap data key: %w", err)
	}

	out, err := json.Marshal(envelope{
		Key:        base64.StdEncoding.EncodeToString(wrappedKey),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}

	return string(out), nil
}
