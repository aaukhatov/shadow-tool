package shadowflow

import (
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

// todo: Fix this test
//func TestPublicKeyEncryptionService(t *testing.T) {
//	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
//	if err != nil {
//		t.Fatalf("Failed to generate RSA keys: %v", err)
//	}
//
//	publicKeyEncryption := NewPublicKeyEncryptionService(&privateKey.PublicKey)
//
//	diffResult := "'name' update: 'John' -> 'Doe'\n'birth-date' update: '2024-01-01' -> '2024-01-02'\n'Address.number' update: '18' -> '20'"
//
//	encryptedText, err := publicKeyEncryption.Encrypt(diffResult)
//	if err != nil {
//		t.Fatalf("Failed to encrypt plain text: %v", err)
//	}
//
//	decryptedText, err := privateKey.Decrypt(nil, []byte(encryptedText), &rsa.OAEPOptions{Hash: crypto.SHA256})
//	if err != nil {
//		t.Fatalf("Failed to decrypt encrypted text: %v", err)
//	}
//
//	if string(decryptedText) != diffResult {
//		t.Errorf("Decrypted text does not match original plain text: got %v, want %v", string(decryptedText), diffResult)
//	}
//}
