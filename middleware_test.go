package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))

	expected := map[string]string{
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"Cache-Control":             "no-store, max-age=0",
	}
	for header, want := range expected {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("%s: expected %q, got %q", header, want, got)
		}
	}
}

func TestSecurityHeadersDeletesPreExisting(t *testing.T) {
	// securityHeaders deletes Server/X-Powered-By before calling next
	rec := httptest.NewRecorder()
	rec.Header().Set("Server", "nginx")
	rec.Header().Set("X-Powered-By", "Go")

	handler := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// By this point, the middleware has already deleted them
		if w.Header().Get("Server") != "" {
			t.Error("Server header should be deleted before handler")
		}
		if w.Header().Get("X-Powered-By") != "" {
			t.Error("X-Powered-By should be deleted before handler")
		}
	}))
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
}

func TestRequireOpsAgentBlocksNodeAgent(t *testing.T) {
	userID := 42
	agent := &AgentPrincipal{ID: 1, Name: "node-agent", TrustLevel: "read", UserID: &userID}
	handler := requireOpsAgent(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ops/agents", nil)
	ctx := context.WithValue(req.Context(), ctxAgentPrincipal, agent)
	handler.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != 403 {
		t.Errorf("expected 403 for node agent, got %d", rec.Code)
	}
}

func TestRequireOpsAgentAllowsSystemAgent(t *testing.T) {
	agent := &AgentPrincipal{ID: 1, Name: "ops-agent", TrustLevel: "read", UserID: nil}
	handler := requireOpsAgent(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ops/agents", nil)
	ctx := context.WithValue(req.Context(), ctxAgentPrincipal, agent)
	handler.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != 200 {
		t.Errorf("expected 200 for system agent, got %d", rec.Code)
	}
}

func TestRequireWriteTrustBlocksRead(t *testing.T) {
	agent := &AgentPrincipal{ID: 1, Name: "read-agent", TrustLevel: "read"}
	handler := requireWriteTrust(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/ops/sessions/revoke", nil)
	ctx := context.WithValue(req.Context(), ctxAgentPrincipal, agent)
	handler.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != 403 {
		t.Errorf("expected 403 for read trust, got %d", rec.Code)
	}
}

func TestRequireWriteTrustAllowsWrite(t *testing.T) {
	agent := &AgentPrincipal{ID: 1, Name: "write-agent", TrustLevel: "write"}
	handler := requireWriteTrust(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/ops/sessions/revoke", nil)
	ctx := context.WithValue(req.Context(), ctxAgentPrincipal, agent)
	handler.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != 200 {
		t.Errorf("expected 200 for write trust, got %d", rec.Code)
	}
}

func TestControlGuardBlocksNonAdmin(t *testing.T) {
	cfg = &Config{}
	handler := controlGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	// No claims at all
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ops/control", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("expected 404 with no claims, got %d", rec.Code)
	}

	// Non-admin user (uid != 1)
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/ops/control", nil)
	ctx := context.WithValue(req.Context(), ctxClaims, &TokenClaims{UID: 99, SID: "s"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 404 {
		t.Errorf("expected 404 for non-admin, got %d", rec.Code)
	}
}

func TestControlGuardAllowsAdmin(t *testing.T) {
	cfg = &Config{}
	handler := controlGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ops/control", nil)
	ctx := context.WithValue(req.Context(), ctxClaims, &TokenClaims{UID: 1, SID: "s"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 200 {
		t.Errorf("expected 200 for admin, got %d", rec.Code)
	}
}

func TestControlGuardIPAllowlist(t *testing.T) {
	cfg = &Config{AllowedIPs: map[string]bool{"10.0.0.1": true}}
	handler := controlGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	// Allowed IP
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ops/control", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	ctx := context.WithValue(req.Context(), ctxClaims, &TokenClaims{UID: 1, SID: "s"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 200 {
		t.Errorf("expected 200 for allowed IP, got %d", rec.Code)
	}

	// Blocked IP
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/ops/control", nil)
	req.RemoteAddr = "99.99.99.99:12345"
	ctx = context.WithValue(req.Context(), ctxClaims, &TokenClaims{UID: 1, SID: "s"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 404 {
		t.Errorf("expected 404 for blocked IP, got %d", rec.Code)
	}

	// Spoofed X-Forwarded-For must not bypass allowlist
	rec = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/ops/control", nil)
	req.RemoteAddr = "99.99.99.99:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	ctx = context.WithValue(req.Context(), ctxClaims, &TokenClaims{UID: 1, SID: "s"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != 404 {
		t.Errorf("expected 404 for spoofed X-Forwarded-For, got %d", rec.Code)
	}
}

func TestCloakOpsHidesWhenDisabled(t *testing.T) {
	cfg = &Config{AgentSecret: ""}
	handler := cloakOps(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/ops/agents", nil))
	if rec.Code != 404 {
		t.Errorf("expected 404 when ops disabled, got %d", rec.Code)
	}
}

func TestCloakOpsPassesThroughWhenEnabled(t *testing.T) {
	cfg = &Config{AgentSecret: "secret"}
	handler := cloakOps(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/ops/agents", nil))
	if rec.Code != 200 {
		t.Errorf("expected 200 when ops enabled, got %d", rec.Code)
	}
}

func TestRateLimit(t *testing.T) {
	cfg = &Config{}
	rl := rateLimit(rateConfig{Window: 60000000000, Max: 3, Prefix: "test"})
	handler := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.99:1234"
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 4th request should be rate limited
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.99:1234"
	handler.ServeHTTP(rec, req)
	if rec.Code != 429 {
		t.Errorf("expected 429 after rate limit exceeded, got %d", rec.Code)
	}
}
