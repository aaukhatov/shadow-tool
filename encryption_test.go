package shadowflow

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestNoopEncryptAndDecrypt(t *testing.T) {
	noopEncryptionService := NewNoopEncryptionService()
	encrypted, _ := noopEncryptionService.Encrypt("'name' update: 'John' -> 'Doe'\n'birth-date' update: '2024-01-01' -> '2024-01-02'\n'Address.number' update: '18' -> '20'")
	if encrypted == "J25hbWUnIHVwZGF0ZTogJ0pvaG4nIC0+ICdEb2UnCidiaXJ0aC1kYXRlJyB1cGRhdGU6ICcyMDI0LTAxLTAxJyAtPiAnMjAyNC0wMS0wMicKJ0FkZHJlc3MubnVtYmVyJyB1cGRhdGU6ICcxOCcgLT4gJzIwJw==" {
		t.Log("Encryption successful")
	} else {
		t.Error("Encryption failed")
	}
}

func TestPublicKeyCannotBeNil(t *testing.T) {
	_, err := NewPublicKeyEncryptionService(nil)
	if err == nil {
		t.Errorf("Expected error when creating the encryption service with a nil public key")
	}
}

func TestPublicKeyMustBeAtLeast2048Bits(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak key: rejecting it is the case under test
	if err != nil {
		t.Fatalf("Failed to generate RSA keys %v", err)
	}

	_, err = NewPublicKeyEncryptionService(&privateKey.PublicKey)
	if err == nil {
		t.Errorf("Expected error when creating the encryption service with a 1024-bit public key")
	}
}

func TestShouldDecryptEncodedText(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Errorf("Failed to generate RSA keys %v", err)
	}

	publicKeyEncryption, err := NewPublicKeyEncryptionService(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create the encryption service %v", err)
	}

	diffResult := "'name' update: 'John' -> 'Doe'\n'birth-date' update: '2024-01-01' -> '2024-01-02'\n'Address.number' update: '18' -> '20'"

	// it's base64 encoded in the end
	encryptedText, err := publicKeyEncryption.Encrypt(diffResult)
	if err != nil {
		t.Errorf("Failed to encrypt plain text %v", err)
	}

	decodedText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		t.Errorf("Failed to parse base64 %v", err)
	}

	decryptedText, err := privateKey.Decrypt(nil, decodedText, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Errorf("Failed to decrypt encrypted text %v", err)
	}

	if string(decryptedText) != diffResult {
		t.Errorf("Decrypted text does not match original plain text actual: %v, expected: %v", string(decryptedText), diffResult)
	}
}

func TestKeyFingerprintMatchesDEREncodedPublicKeyHash(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys %v", err)
	}

	publicKeyEncryption, err := NewPublicKeyEncryptionService(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create the encryption service %v", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key %v", err)
	}
	sum := sha256.Sum256(derBytes)
	expected := hex.EncodeToString(sum[:8])

	if fingerprint := publicKeyEncryption.KeyFingerprint(); fingerprint != expected {
		t.Errorf("Expected key fingerprint %q, got %q", expected, fingerprint)
	}

	// Deterministic: calling it again returns the same value.
	if fingerprint := publicKeyEncryption.KeyFingerprint(); fingerprint != expected {
		t.Errorf("Expected key fingerprint to stay %q, got %q", expected, fingerprint)
	}
}

func TestKeyFingerprintDiffersBetweenKeys(t *testing.T) {
	privateKeyA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys %v", err)
	}
	privateKeyB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys %v", err)
	}

	serviceA, err := NewPublicKeyEncryptionService(&privateKeyA.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create the encryption service %v", err)
	}
	serviceB, err := NewPublicKeyEncryptionService(&privateKeyB.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create the encryption service %v", err)
	}

	if serviceA.KeyFingerprint() == serviceB.KeyFingerprint() {
		t.Errorf("Expected different keys to produce different fingerprints, both were %q", serviceA.KeyFingerprint())
	}
}
