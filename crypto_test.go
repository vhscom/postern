package main

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	hash, err := hashPassword("Test123!@#")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$pbkdf2-sha384$v1$210000$") {
		t.Fatalf("unexpected format: %s", hash)
	}
	if !verifyPassword("Test123!@#", hash) {
		t.Error("correct password should verify")
	}
	if verifyPassword("wrong", hash) {
		t.Error("wrong password should not verify")
	}
}

func TestPasswordNormalization(t *testing.T) {
	// Multiple spaces → single space
	hash, _ := hashPassword("pass  word  here")
	if !verifyPassword("pass word here", hash) {
		t.Error("normalized password should verify")
	}
}

func TestVerifyPasswordBadFormat(t *testing.T) {
	if verifyPassword("anything", "not-a-valid-hash") {
		t.Error("bad format should return false")
	}
}

func TestRejectConstantTime(t *testing.T) {
	// Should not panic, should complete in reasonable time
	rejectConstantTime("test-password")
}

func TestSignAndVerifyToken(t *testing.T) {
	secret := "test-secret"
	token, err := signToken(42, "sess-1", "access", secret, accessExpiry)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := verifyToken(token, secret, "access")
	if err != nil {
		t.Fatal(err)
	}
	if claims.UID != 42 || claims.SID != "sess-1" || claims.Typ != "access" {
		t.Errorf("unexpected claims: uid=%d sid=%s typ=%s", claims.UID, claims.SID, claims.Typ)
	}
}

func TestVerifyTokenWrongType(t *testing.T) {
	secret := "test-secret"
	token, _ := signToken(1, "s", "refresh", secret, refreshExpiry)
	_, err := verifyToken(token, secret, "access")
	if err == nil {
		t.Error("should reject wrong token type")
	}
}

func TestVerifyTokenWrongSecret(t *testing.T) {
	token, _ := signToken(1, "s", "access", "secret-a", accessExpiry)
	_, err := verifyToken(token, "secret-b", "access")
	if err == nil {
		t.Error("should reject wrong secret")
	}
}

func TestHashAPIKey(t *testing.T) {
	h := hashAPIKey("test-key")
	if len(h) != 64 { // SHA-256 hex = 64 chars
		t.Errorf("expected 64 hex chars, got %d", len(h))
	}
	// Deterministic
	if hashAPIKey("test-key") != h {
		t.Error("hash should be deterministic")
	}
}

func TestInjectToken(t *testing.T) {
	t.Run("connect frame gets token", func(t *testing.T) {
		in := `{"type":"req","method":"connect","params":{"auth":{"token":"old"}}}`
		out := string(injectToken([]byte(in), "SECRET"))
		if !strings.Contains(out, `"token":"SECRET"`) {
			t.Errorf("token not injected: %s", out)
		}
		if strings.Contains(out, "old") {
			t.Error("old token should be replaced")
		}
	})

	t.Run("non-connect passes through", func(t *testing.T) {
		in := `{"type":"req","method":"subscribe","params":{}}`
		out := string(injectToken([]byte(in), "SECRET"))
		if out != in {
			t.Errorf("should pass through: %s", out)
		}
	})

	t.Run("non-JSON passes through", func(t *testing.T) {
		in := `hello`
		out := string(injectToken([]byte(in), "SECRET"))
		if out != in {
			t.Error("should pass through")
		}
	})
}
