package main

import "testing"

func TestRevokeSessionsInvalidScope(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	_, code, msg := revokeSessions("invalid", nil)
	if code != "INVALID_SCOPE" {
		t.Errorf("code = %q, want INVALID_SCOPE", code)
	}
	if msg == "" {
		t.Error("expected error message")
	}
}

func TestRevokeSessionsUserRequiresID(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	_, code, _ := revokeSessions("user", nil)
	if code != "INVALID_ID" {
		t.Errorf("code = %q, want INVALID_ID", code)
	}
}

func TestRevokeSessionsSessionRequiresID(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	_, code, _ := revokeSessions("session", nil)
	if code != "INVALID_ID" {
		t.Errorf("code = %q, want INVALID_ID", code)
	}

	_, code, _ = revokeSessions("session", "")
	if code != "INVALID_ID" {
		t.Errorf("code = %q for empty string, want INVALID_ID", code)
	}
}

func TestRevokeSessionsAll(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	// Create an account and session
	store.Exec("INSERT INTO account (email, password_data) VALUES ('rev@test.com', 'x')")
	createSession(1, "ua", "127.0.0.1")

	count, code, _ := revokeSessions("all", nil)
	if code != "" {
		t.Errorf("unexpected error: %s", code)
	}
	if count < 1 {
		t.Errorf("expected at least 1 revoked session, got %d", count)
	}
}
