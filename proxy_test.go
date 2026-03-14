package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProxyStripsHopByHopHeaders(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg = &Config{GatewayURL: upstream.URL}
	proxy := newProxy()

	req := httptest.NewRequest("GET", "/ops/control/test", nil)
	for _, h := range hopByHop {
		req.Header.Set(h, "should-be-stripped")
	}
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	for _, h := range hopByHop {
		if v := gotHeaders.Get(h); v != "" {
			t.Errorf("hop-by-hop header %q leaked upstream: %q", h, v)
		}
	}
}

func TestProxyStripsCredentials(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg = &Config{GatewayURL: upstream.URL}
	proxy := newProxy()

	req := httptest.NewRequest("GET", "/ops/control/", nil)
	req.Header.Set("Cookie", "access_token=secret")
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if v := gotHeaders.Get("Cookie"); v != "" {
		t.Errorf("Cookie leaked upstream: %q", v)
	}
	if v := gotHeaders.Get("Authorization"); v != "" {
		t.Errorf("Authorization leaked upstream: %q", v)
	}
}

func TestProxyStripsClientForwardedHeaders(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg = &Config{GatewayURL: upstream.URL}
	proxy := newProxy()

	req := httptest.NewRequest("GET", "/ops/control/", nil)
	req.Header.Set("X-Forwarded-For", "evil-spoofed-ip")
	req.Header.Set("X-Forwarded-Proto", "ftp")
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-Real-IP", "6.6.6.6")
	req.Header.Set("Forwarded", "for=6.6.6.6")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	// Client-supplied values must be replaced, not forwarded
	if v := gotHeaders.Get("X-Real-IP"); v == "6.6.6.6" {
		t.Error("client X-Real-IP was forwarded as-is")
	}
	if v := gotHeaders.Get("Forwarded"); v == "for=6.6.6.6" {
		t.Error("client Forwarded header was forwarded as-is")
	}
	if v := gotHeaders.Get("X-Forwarded-Host"); v == "evil.com" {
		t.Error("client X-Forwarded-Host was forwarded as-is")
	}
}

func TestProxyStripsConnectionListedHeaders(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg = &Config{GatewayURL: upstream.URL}
	proxy := newProxy()

	req := httptest.NewRequest("GET", "/ops/control/", nil)
	req.Header.Set("Connection", "X-Custom-Secret, Keep-Alive")
	req.Header.Set("X-Custom-Secret", "sensitive-value")
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if v := gotHeaders.Get("X-Custom-Secret"); v != "" {
		t.Errorf("Connection-listed header leaked upstream: %q", v)
	}
}

func TestProxyStripsResponseHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=hijack; Path=/")
		w.Header().Set("Server", "nginx/1.2.3")
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("X-App-Data", "safe-to-forward")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg = &Config{GatewayURL: upstream.URL}
	proxy := newProxy()

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/ops/control/", nil))

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	for _, h := range []string{"Set-Cookie", "Server", "X-Powered-By"} {
		if v := rec.Header().Get(h); v != "" {
			t.Errorf("response header %q leaked to client: %q", h, v)
		}
	}
	if v := rec.Header().Get("X-App-Data"); v != "safe-to-forward" {
		t.Errorf("expected X-App-Data to pass through, got %q", v)
	}
}

func TestProxyPathRewrite(t *testing.T) {
	var gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	cfg = &Config{GatewayURL: upstream.URL}
	proxy := newProxy()

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/ops/control/api/v1/status", nil))

	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotPath != "/api/v1/status" {
		t.Errorf("expected path /api/v1/status, got %q", gotPath)
	}
}

func TestProxyReturns404WhenDisabled(t *testing.T) {
	cfg = &Config{GatewayURL: ""}
	proxy := newProxy()

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/ops/control/", nil))

	if rec.Code != 404 {
		t.Errorf("expected 404 when gateway disabled, got %d", rec.Code)
	}
}

func TestProxyUpstreamError(t *testing.T) {
	cfg = &Config{GatewayURL: "http://127.0.0.1:1"} // nothing listening
	proxy := newProxy()

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest("GET", "/ops/control/", nil))

	if rec.Code != 502 {
		t.Errorf("expected 502 on upstream error, got %d", rec.Code)
	}
}
