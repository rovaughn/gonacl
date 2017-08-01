package pwhash

import (
	"log"
	"testing"
)

func TestHash(t *testing.T) {
	hash, ok := Hash("password", OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)
	if !ok {
		t.Error("Should have succeeded")
	}

	if !Verify(hash, "password") {
		t.Error("Should be true")
	}

	if Verify(hash, "password?") {
		t.Error("Should be false")
	}
}
