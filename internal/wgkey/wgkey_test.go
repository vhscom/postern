package wgkey

import (
	"encoding/base64"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// Both keys should be valid base64 of 32 bytes
	privBytes, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(privBytes) != 32 {
		t.Fatalf("private key: invalid base64 or wrong length (%d)", len(privBytes))
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(pubBytes) != 32 {
		t.Fatalf("public key: invalid base64 or wrong length (%d)", len(pubBytes))
	}

	// Verify clamping bits
	if privBytes[0]&7 != 0 {
		t.Error("private key: low 3 bits of first byte should be cleared")
	}
	if privBytes[31]&128 != 0 {
		t.Error("private key: high bit of last byte should be cleared")
	}
	if privBytes[31]&64 == 0 {
		t.Error("private key: bit 6 of last byte should be set")
	}
}

func TestGenerateKeypairUniqueness(t *testing.T) {
	_, pub1, _ := GenerateKeypair()
	_, pub2, _ := GenerateKeypair()
	if pub1 == pub2 {
		t.Error("two generated keypairs should not have the same public key")
	}
}
