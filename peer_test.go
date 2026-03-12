package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupPeerServer(t *testing.T) (*httptest.Server, []*http.Cookie) {
	t.Helper()

	cfg = &Config{
		Addr:          ":0",
		DBPath:        ":memory:",
		AccessSecret:  "test-access",
		RefreshSecret: "test-refresh",
		CookieSecure:  false,
		Environment:   "development",
	}
	initDB(cfg.DBPath)

	mux := http.NewServeMux()
	mux.Handle("POST /auth/register", http.HandlerFunc(handleRegister))
	mux.Handle("POST /auth/login", http.HandlerFunc(handleLogin))
	mux.Handle("GET /account/peers", requireAuthMiddleware(http.HandlerFunc(handlePeerList)))
	mux.Handle("PUT /account/peers", requireAuthMiddleware(http.HandlerFunc(handlePeerUpsert)))
	mux.Handle("DELETE /account/peers/{label}", requireAuthMiddleware(http.HandlerFunc(handlePeerDelete)))
	srv := httptest.NewServer(mux)

	// Register and login
	jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "peer@test.com", "password": "password123",
	}, nil)
	resp, _ := jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "peer@test.com", "password": "password123",
	}, nil)

	return srv, resp.Cookies()
}

func jsonPut(url string, body any, cookies []*http.Cookie) (*http.Response, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Do(req)
	var result map[string]any
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(raw, &result)
	return resp, result
}

func jsonDelete(url string, cookies []*http.Cookie) (*http.Response, map[string]any) {
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Do(req)
	var result map[string]any
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(raw, &result)
	return resp, result
}

func TestPeerListEmpty(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	resp, body := jsonGet(srv.URL+"/account/peers", cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	peers := body["peers"].([]any)
	if len(peers) != 0 {
		t.Errorf("expected 0 peers, got %d", len(peers))
	}
	if body["tier"] != "free" {
		t.Errorf("expected free tier, got %v", body["tier"])
	}
	if body["limit"].(float64) != 1 {
		t.Errorf("expected limit 1, got %v", body["limit"])
	}
}

func TestPeerCreate(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "home",
		"endpoint":  "192.168.1.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d: %v", resp.StatusCode, body)
	}
	if body["label"] != "home" {
		t.Errorf("expected label 'home', got %v", body["label"])
	}

	// Verify in list
	resp, body = jsonGet(srv.URL+"/account/peers", cookies)
	peers := body["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	peer := peers[0].(map[string]any)
	if peer["endpoint"] != "192.168.1.1:51820" {
		t.Errorf("unexpected endpoint: %v", peer["endpoint"])
	}
}

func TestPeerUpdate(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	// Create
	jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "home",
		"endpoint":  "192.168.1.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)

	// Update same label without confirm — should get 409
	resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "home",
		"endpoint":  "10.0.0.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)
	if resp.StatusCode != 409 {
		t.Fatalf("update without confirm: expected 409, got %d", resp.StatusCode)
	}
	if body["code"] != "PEER_EXISTS" {
		t.Errorf("expected PEER_EXISTS code, got %v", body["code"])
	}
	existing := body["existing"].(map[string]any)
	if existing["endpoint"] != "192.168.1.1:51820" {
		t.Errorf("expected existing endpoint, got %v", existing["endpoint"])
	}

	// Update same label with confirm — should succeed
	resp, _ = jsonPut(srv.URL+"/account/peers", map[string]any{
		"label":     "home",
		"endpoint":  "10.0.0.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"confirm":   true,
	}, cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("update with confirm: expected 200, got %d", resp.StatusCode)
	}

	// Verify updated
	_, body = jsonGet(srv.URL+"/account/peers", cookies)
	peer := body["peers"].([]any)[0].(map[string]any)
	if peer["endpoint"] != "10.0.0.1:51820" {
		t.Errorf("expected updated endpoint, got %v", peer["endpoint"])
	}
}

func TestPeerDelete(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "home",
		"endpoint":  "192.168.1.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)

	resp, body := jsonDelete(srv.URL+"/account/peers/home", cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("delete: expected 200, got %d: %v", resp.StatusCode, body)
	}

	// Verify gone
	_, body = jsonGet(srv.URL+"/account/peers", cookies)
	peers := body["peers"].([]any)
	if len(peers) != 0 {
		t.Error("expected 0 peers after delete")
	}
}

func TestPeerDeleteNotFound(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	resp, _ := jsonDelete(srv.URL+"/account/peers/nope", cookies)
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestPeerFreeTierLimit(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	// First peer — should succeed
	resp, _ := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "home",
		"endpoint":  "192.168.1.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)
	if resp.StatusCode != 201 {
		t.Fatalf("first peer: expected 201, got %d", resp.StatusCode)
	}

	// Second peer — should hit 402
	resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "vps",
		"endpoint":  "10.0.0.1:51820",
		"wg_pubkey": "VGVzdEtleUZvclBvc3Rlcm5QZWVyVmFsaWRhdGlvbiE=",
	}, cookies)
	if resp.StatusCode != 402 {
		t.Fatalf("tier limit: expected 402, got %d: %v", resp.StatusCode, body)
	}
	if body["code"] != "TIER_LIMIT" {
		t.Errorf("expected TIER_LIMIT code, got %v", body["code"])
	}
}

func TestPeerProTierAllowsMultiple(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	// Manually set pro tier
	store.Exec("INSERT INTO user_subscription (user_id, stripe_customer_id, tier) VALUES (1, 'test_cus', 'pro')")

	for i, label := range []string{"home", "vps", "travel"} {
		resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
			"label":     label,
			"endpoint":  "10.0.0.1:51820",
			"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		}, cookies)
		if resp.StatusCode != 201 {
			t.Fatalf("peer %d (%s): expected 201, got %d: %v", i, label, resp.StatusCode, body)
		}
	}

	// Verify all three
	_, body := jsonGet(srv.URL+"/account/peers", cookies)
	peers := body["peers"].([]any)
	if len(peers) != 3 {
		t.Errorf("expected 3 peers, got %d", len(peers))
	}
	if body["tier"] != "pro" {
		t.Errorf("expected pro tier, got %v", body["tier"])
	}
}

func TestPeerValidationBadWGKey(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "bad",
		"endpoint":  "10.0.0.1:51820",
		"wg_pubkey": "not-a-valid-key",
	}, cookies)
	if resp.StatusCode != 400 {
		t.Errorf("bad wg key: expected 400, got %d: %v", resp.StatusCode, body)
	}
}

func TestPeerValidationBadEndpoint(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "bad",
		"endpoint":  "no-port",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)
	if resp.StatusCode != 400 {
		t.Errorf("bad endpoint: expected 400, got %d: %v", resp.StatusCode, body)
	}
}

func TestPeerValidationBadLabel(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "has spaces",
		"endpoint":  "10.0.0.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)
	if resp.StatusCode != 400 {
		t.Errorf("bad label: expected 400, got %d: %v", resp.StatusCode, body)
	}
}

func TestPeerDefaultLabel(t *testing.T) {
	srv, cookies := setupPeerServer(t)
	defer srv.Close()

	// Empty label should default to "default"
	resp, body := jsonPut(srv.URL+"/account/peers", map[string]string{
		"label":     "",
		"endpoint":  "10.0.0.1:51820",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d: %v", resp.StatusCode, body)
	}
	if body["label"] != "default" {
		t.Errorf("expected label 'default', got %v", body["label"])
	}
}

func TestPeerUnauthenticated(t *testing.T) {
	srv, _ := setupPeerServer(t)
	defer srv.Close()

	resp, _ := jsonGet(srv.URL+"/account/peers", nil)
	if resp.StatusCode != 401 {
		t.Errorf("list: expected 401, got %d", resp.StatusCode)
	}

	resp, _ = jsonPut(srv.URL+"/account/peers", map[string]string{
		"label": "x", "endpoint": "x:1", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, nil)
	if resp.StatusCode != 401 {
		t.Errorf("put: expected 401, got %d", resp.StatusCode)
	}

	resp, _ = jsonDelete(srv.URL+"/account/peers/x", nil)
	if resp.StatusCode != 401 {
		t.Errorf("delete: expected 401, got %d", resp.StatusCode)
	}
}

func TestGetUserTierDefault(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	tier := getUserTier(999)
	if tier != "free" {
		t.Errorf("expected free for unknown user, got %s", tier)
	}
}

func TestPeerLimitByTier(t *testing.T) {
	if peerLimit("free") != 1 {
		t.Errorf("free: expected 1, got %d", peerLimit("free"))
	}
	if peerLimit("pro") != 10 {
		t.Errorf("pro: expected 10, got %d", peerLimit("pro"))
	}
	if peerLimit("team") != 25 {
		t.Errorf("team: expected 25, got %d", peerLimit("team"))
	}
	if peerLimit("unknown") != 1 {
		t.Errorf("unknown: expected 1, got %d", peerLimit("unknown"))
	}
}
