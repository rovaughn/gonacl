package pwhash

import (
	"testing"
)

func TestHash(t *testing.T) {
	hash := make([]byte, Size)
	n, ok := Hash(hash, []byte("password"), OpsLimitInteractive, MemLimitInteractive)
	if !ok {
		t.Error("Should have succeeded")
	}

	if !Verify(hash[:n], []byte("password")) {
		t.Error("Should be true")
	}

	if Verify(hash[:n], []byte("password?")) {
		t.Error("Should be false")
	}
}
