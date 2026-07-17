package shadowflow

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// decryptEnvelope reverses PublicKeyEncryptionService.Encrypt: it parses the
// JSON envelope, RSA-OAEP-decrypts the wrapped data key, and AES-GCM-opens
// the ciphertext with it. Used by tests to prove the encrypted output
// round-trips correctly.
func decryptEnvelope(t *testing.T, privateKey *rsa.PrivateKey, encoded string) string {
	t.Helper()

	var env envelope
	if err := json.Unmarshal([]byte(encoded), &env); err != nil {
		t.Fatalf("Failed to parse envelope JSON %v", err)
	}

	wrappedKey, err := base64.StdEncoding.DecodeString(env.Key)
	if err != nil {
		t.Fatalf("Failed to decode envelope key %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		t.Fatalf("Failed to decode envelope nonce %v", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		t.Fatalf("Failed to decode envelope ciphertext %v", err)
	}

	dataKey, err := privateKey.Decrypt(nil, wrappedKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("Failed to unwrap data key %v", err)
	}

	block, err := aes.NewCipher(dataKey)
	if err != nil {
		t.Fatalf("Failed to create AES cipher %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM %v", err)
	}

	plainText, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext %v", err)
	}

	return string(plainText)
}

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

	encryptedText, err := publicKeyEncryption.Encrypt(diffResult)
	if err != nil {
		t.Errorf("Failed to encrypt plain text %v", err)
	}

	decryptedText := decryptEnvelope(t, privateKey, encryptedText)
	if decryptedText != diffResult {
		t.Errorf("Decrypted text does not match original plain text actual: %v, expected: %v", decryptedText, diffResult)
	}
}

// TestEncryptPayloadLargerThanOAEPLimit is the regression test for the bug
// where Encrypt used to RSA-OAEP-encrypt the payload directly: OAEP with
// SHA-256 caps plaintext at 190 bytes for a 2048-bit key, so any non-trivial
// diff returned rsa.ErrMessageTooLong and the values were dropped. With
// envelope encryption only the small AES data key goes through RSA, so
// payloads far past that limit must still encrypt and decrypt correctly.
func TestEncryptPayloadLargerThanOAEPLimit(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA keys %v", err)
	}

	publicKeyEncryption, err := NewPublicKeyEncryptionService(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to create the encryption service %v", err)
	}

	line := "'field' update: 'some reasonably long previous value' -> 'some reasonably long new value'\n"
	diffResult := strings.Repeat(line, 20) // well over the 190-byte OAEP limit
	if len(diffResult) <= 190 {
		t.Fatalf("test payload must exceed the 190-byte OAEP limit, got %d bytes", len(diffResult))
	}

	encryptedText, err := publicKeyEncryption.Encrypt(diffResult)
	if err != nil {
		t.Fatalf("Encrypt should not fail for large payloads with envelope encryption, got %v", err)
	}

	decryptedText := decryptEnvelope(t, privateKey, encryptedText)
	if decryptedText != diffResult {
		t.Errorf("Decrypted text does not match original plain text actual: %v, expected: %v", decryptedText, diffResult)
	}
}
