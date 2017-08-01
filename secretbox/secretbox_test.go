package secretbox

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSealAndOpen(t *testing.T) {
	nonce := make([]byte, NonceSize)
	key := make([]byte, KeySize)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal("Failed to read nonce")
	}
	if _, err := rand.Read(key); err != nil {
		t.Fatal("Failed to read key")
	}
	message := []byte("attack at dawn")
	ciphertext := make([]byte, MacSize+len(message))
	Seal(ciphertext, message, nonce, key)
	deciphered := make([]byte, len(message))
	if ok := Open(deciphered, ciphertext, nonce, key); !ok {
		t.Error("Open should've succeeded")
	} else if !bytes.Equal(deciphered, message) {
		t.Error("deciphering was incorrect")
	}
}
