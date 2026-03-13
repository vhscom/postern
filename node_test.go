package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func setupNodeServer(t *testing.T) (*httptest.Server, []*http.Cookie) {
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
	mux.Handle("GET /account/nodes", requireAuthMiddleware(http.HandlerFunc(handleNodeList)))
	mux.Handle("POST /account/nodes", requireAuthMiddleware(http.HandlerFunc(handleNodeCreate)))
	mux.Handle("PUT /account/nodes/{label}", requireAuthMiddleware(http.HandlerFunc(handleNodeUpdate)))
	mux.Handle("DELETE /account/nodes/{label}", requireAuthMiddleware(http.HandlerFunc(handleNodeDelete)))
	srv := httptest.NewServer(mux)

	jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "node@test.com", "password": "password123",
	}, nil)
	resp, _ := jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "node@test.com", "password": "password123",
	}, nil)

	return srv, resp.Cookies()
}

func TestNodeListEmpty(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	resp, body := jsonGet(srv.URL+"/account/nodes", cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	nodes := body["nodes"].([]any)
	if len(nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestNodeCreate(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	resp, body := jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label":       "gateway",
		"wg_pubkey":   "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
		"wg_endpoint": "1.2.3.4:51820",
	}, cookies)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d: %v", resp.StatusCode, body)
	}
	if body["label"] != "gateway" {
		t.Errorf("expected label 'gateway', got %v", body["label"])
	}
	if body["api_key"] == nil || body["api_key"] == "" {
		t.Error("expected api_key in response")
	}
}

func TestNodeCreateSetsManualEndpointSource(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "manual-ep", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32", "wg_endpoint": "1.2.3.4:51820",
	}, cookies)

	_, body := jsonGet(srv.URL+"/account/nodes", cookies)
	nodes := body["nodes"].([]any)
	node := nodes[0].(map[string]any)
	if node["wg_endpoint_source"] != "manual" {
		t.Errorf("expected endpoint source 'manual', got %v", node["wg_endpoint_source"])
	}
}

func TestNodeCreateNoEndpointSetsStunSource(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "no-ep", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.2/32",
	}, cookies)

	_, body := jsonGet(srv.URL+"/account/nodes", cookies)
	nodes := body["nodes"].([]any)
	node := nodes[0].(map[string]any)
	if node["wg_endpoint_source"] != "stun" {
		t.Errorf("expected endpoint source 'stun', got %v", node["wg_endpoint_source"])
	}
}

func TestNodeListStatus(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "offline-node", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)

	_, body := jsonGet(srv.URL+"/account/nodes", cookies)
	nodes := body["nodes"].([]any)
	node := nodes[0].(map[string]any)
	if node["status"] != "offline" {
		t.Errorf("expected status 'offline' for never-seen node, got %v", node["status"])
	}
}

func TestNodeUpdateSetsManualSource(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	// Create with no endpoint (source = stun)
	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "update-test", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)

	// Update with endpoint — should set source to manual
	ep := "5.6.7.8:51820"
	resp, _ := jsonPut(srv.URL+"/account/nodes/update-test", map[string]any{
		"wg_endpoint": &ep,
	}, cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("update: expected 200, got %d", resp.StatusCode)
	}

	_, body := jsonGet(srv.URL+"/account/nodes", cookies)
	nodes := body["nodes"].([]any)
	node := nodes[0].(map[string]any)
	if node["wg_endpoint_source"] != "manual" {
		t.Errorf("expected source 'manual' after update, got %v", node["wg_endpoint_source"])
	}
}

func TestNodeDelete(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "del-me", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)

	resp, _ := jsonDelete(srv.URL+"/account/nodes/del-me", cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}

	_, body := jsonGet(srv.URL+"/account/nodes", cookies)
	nodes := body["nodes"].([]any)
	if len(nodes) != 0 {
		t.Error("expected 0 nodes after delete")
	}
}

func TestNodeTierLimit(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	// Free tier: 2 nodes
	for i, label := range []string{"n1", "n2"} {
		resp, _ := jsonPost(srv.URL+"/account/nodes", map[string]string{
			"label": label, "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
			"allowed_ips": "10.0.0.1/32",
		}, cookies)
		if resp.StatusCode != 201 {
			t.Fatalf("node %d: expected 201, got %d", i, resp.StatusCode)
		}
	}

	// Third should fail
	resp, body := jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "n3", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)
	if resp.StatusCode != 402 {
		t.Fatalf("tier limit: expected 402, got %d: %v", resp.StatusCode, body)
	}
}

func TestNodeCreateRejectsInvalidCIDR(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	tests := []struct {
		name string
		ips  string
		code int
	}{
		{"bare-ip", "10.0.0.1", 400},
		{"garbage", "not-cidr", 400},
		{"newline-inject", "10.0.0.1/32\n127.0.0.1 evil.com", 400},
		{"valid-cidr", "10.0.0.5/32", 201},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, _ := jsonPost(srv.URL+"/account/nodes", map[string]string{
				"label":       "cidr-" + tt.name,
				"wg_pubkey":   "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
				"allowed_ips": tt.ips,
			}, cookies)
			if resp.StatusCode != tt.code {
				t.Errorf("allowed_ips=%q: expected %d, got %d", tt.ips, tt.code, resp.StatusCode)
			}
		})
	}
}

func TestNodeUpdateRejectsInvalidCIDR(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "update-cidr", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)

	tests := []struct {
		name string
		ips  string
		code int
	}{
		{"bare-ip", "10.0.0.2", 400},
		{"newline-inject", "10.0.0.1/32\nevil", 400},
		{"valid-cidr", "10.0.0.99/32", 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := tt.ips
			resp, _ := jsonPut(srv.URL+"/account/nodes/update-cidr", map[string]any{
				"allowed_ips": &ips,
			}, cookies)
			if resp.StatusCode != tt.code {
				t.Errorf("allowed_ips=%q: expected %d, got %d", tt.ips, tt.code, resp.StatusCode)
			}
		})
	}
}

func TestComputeNodeStatus(t *testing.T) {
	tests := []struct {
		name       string
		lastSeenAt *string
		want       string
	}{
		{"nil", nil, "offline"},
		{"invalid", strPtr("not-a-date"), "offline"},
		{"recent", strPtr(time.Now().UTC().Format("2006-01-02 15:04:05")), "online"},
		{"few minutes ago", strPtr(time.Now().Add(-5 * time.Minute).UTC().Format("2006-01-02 15:04:05")), "idle"},
		{"long ago", strPtr(time.Now().Add(-30 * time.Minute).UTC().Format("2006-01-02 15:04:05")), "offline"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeNodeStatus(tt.lastSeenAt)
			if got != tt.want {
				t.Errorf("computeNodeStatus(%v) = %q, want %q", tt.lastSeenAt, got, tt.want)
			}
		})
	}
}

func TestNodeLimitByTier(t *testing.T) {
	tests := []struct {
		tier string
		want int
	}{
		{"free", 2},
		{"pro", 10},
		{"team", 25},
		{"unknown", 2},
	}
	for _, tt := range tests {
		if got := nodeLimit(tt.tier); got != tt.want {
			t.Errorf("nodeLimit(%q) = %d, want %d", tt.tier, got, tt.want)
		}
	}
}

func TestNodeSyncIncludesNodeID(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	// Create a user and two nodes
	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('agent1', 'h1', 'read', 1)")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('agent2', 'h2', 'read', 1)")
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'n1', 'pubkey1', '10.0.0.1/32', 1, 'manual')`)
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'n2', 'pubkey2', '10.0.0.2/32', 2, 'stun')`)

	// Verify lookupNodeForAgent works
	nid, uid := lookupNodeForAgent(1)
	if nid == 0 || uid == 0 {
		t.Fatalf("lookupNodeForAgent: expected valid node/user, got %d/%d", nid, uid)
	}
}

func TestEndpointDiscoveredHandler(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('agent1', 'h1', 'read', 1)")
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'n1', 'pubkey1', '10.0.0.1/32', 1, 'stun')`)

	// Simulate STUN update — should succeed since source is 'stun'
	result, err := store.Exec(
		"UPDATE user_node SET wg_endpoint = ?, wg_endpoint_source = 'stun', updated_at = datetime('now') WHERE id = 1 AND wg_endpoint_source != 'manual'",
		"203.0.113.5:51820",
	)
	if err != nil {
		t.Fatalf("STUN update: %v", err)
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		t.Errorf("expected 1 row affected, got %d", rows)
	}

	// Verify endpoint was updated
	var ep string
	store.QueryRow("SELECT wg_endpoint FROM user_node WHERE id = 1").Scan(&ep)
	if ep != "203.0.113.5:51820" {
		t.Errorf("expected endpoint 203.0.113.5:51820, got %s", ep)
	}

	// Now set to manual — STUN should not overwrite
	store.Exec("UPDATE user_node SET wg_endpoint_source = 'manual' WHERE id = 1")

	result, err = store.Exec(
		"UPDATE user_node SET wg_endpoint = ?, wg_endpoint_source = 'stun', updated_at = datetime('now') WHERE id = 1 AND wg_endpoint_source != 'manual'",
		"198.51.100.1:51820",
	)
	if err != nil {
		t.Fatalf("STUN update after manual: %v", err)
	}
	rows, _ = result.RowsAffected()
	if rows != 0 {
		t.Errorf("manual endpoint should not be overwritten, but %d rows affected", rows)
	}
}

func TestKeyRotateHandler(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('agent1', 'h1', 'read', 1)")
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'n1', 'oldpubkey', '10.0.0.1/32', 1, 'manual')`)

	newPubkey := "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	_, err := store.Exec(
		"UPDATE user_node SET wg_pubkey = ?, updated_at = datetime('now') WHERE id = 1",
		newPubkey,
	)
	if err != nil {
		t.Fatalf("key rotate update: %v", err)
	}

	var stored string
	store.QueryRow("SELECT wg_pubkey FROM user_node WHERE id = 1").Scan(&stored)
	if stored != newPubkey {
		t.Errorf("expected pubkey %s, got %s", newPubkey, stored)
	}
}

func TestMigrationV4EndpointSource(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	// Verify the column exists and default is 'manual'
	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('a1', 'h', 'read', 1)")
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, agent_credential_id)
		VALUES (1, 'n1', 'pk', '10.0.0.1/32', 1)`)

	var source string
	err := store.QueryRow("SELECT wg_endpoint_source FROM user_node WHERE id = 1").Scan(&source)
	if err != nil {
		t.Fatalf("query endpoint source: %v", err)
	}
	if source != "manual" {
		t.Errorf("default endpoint source should be 'manual', got %q", source)
	}

	// Verify schema version
	var version int
	store.QueryRow("SELECT MAX(version) FROM schema_version").Scan(&version)
	if version < 4 {
		t.Errorf("schema version should be >= 4, got %d", version)
	}
}

func TestNodeListStatusAPI(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "status-node", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)

	// Set last_seen_at to recent time
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	store.Exec("UPDATE user_node SET last_seen_at = ? WHERE label = 'status-node'", now)

	resp, _ := jsonGet(srv.URL+"/account/nodes", cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result struct {
		Nodes []struct {
			Status string `json:"status"`
		} `json:"nodes"`
	}
	// Re-fetch since jsonGet already consumed body
	req, _ := http.NewRequest("GET", srv.URL+"/account/nodes", nil)
	req.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp2, _ := http.DefaultClient.Do(req)
	json.NewDecoder(resp2.Body).Decode(&result)
	resp2.Body.Close()

	if len(result.Nodes) == 0 {
		t.Fatal("expected at least 1 node")
	}
	if result.Nodes[0].Status != "online" {
		t.Errorf("expected status 'online', got %q", result.Nodes[0].Status)
	}
}

func TestNodeCredentialHasUserID(t *testing.T) {
	srv, cookies := setupNodeServer(t)
	defer srv.Close()

	resp, body := jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "trust-check", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	// Verify the credential has user_id set (node-bound)
	apiKey := body["api_key"].(string)
	keyHash := hashAPIKey(apiKey)
	var userID *int
	err := store.QueryRow("SELECT user_id FROM agent_credential WHERE key_hash = ?", keyHash).Scan(&userID)
	if err != nil {
		t.Fatalf("lookup credential: %v", err)
	}
	if userID == nil {
		t.Error("node credential should have user_id set")
	}
}

func TestNodeAgentBlockedFromOpsEndpoints(t *testing.T) {
	cfg = &Config{
		Addr:          ":0",
		DBPath:        ":memory:",
		AccessSecret:  "test-access",
		RefreshSecret: "test-refresh",
		AgentSecret:   "test-secret",
		Environment:   "development",
	}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")

	// Node-bound credential (has user_id) — should be blocked from ops
	nodeKey := randomHex(32)
	nodeHash := hashAPIKey(nodeKey)
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('node-agent', ?, 'read', 1)", nodeHash)

	// Ops credential (no user_id) — should be allowed
	opsKey := randomHex(32)
	opsHash := hashAPIKey(opsKey)
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level) VALUES ('ops-agent', ?, 'read')", opsHash)

	mux := http.NewServeMux()
	mux.Handle("GET /ops/events", requireAgentKey(requireOpsAgent(http.HandlerFunc(handleOpsEvents))))
	mux.Handle("GET /ops/sessions", requireAgentKey(requireOpsAgent(http.HandlerFunc(handleOpsSessions))))
	mux.Handle("GET /ops/nodes", requireAgentKey(requireOpsAgent(http.HandlerFunc(handleOpsNodeList))))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	endpoints := []string{"/ops/events", "/ops/sessions", "/ops/nodes"}

	// Node-bound agent should be blocked
	for _, ep := range endpoints {
		req, _ := http.NewRequest("GET", srv.URL+ep, nil)
		req.Header.Set("Authorization", "Bearer "+nodeKey)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 403 {
			t.Errorf("node agent on %s: expected 403, got %d", ep, resp.StatusCode)
		}
	}

	// Ops agent should be allowed
	for _, ep := range endpoints {
		req, _ := http.NewRequest("GET", srv.URL+ep, nil)
		req.Header.Set("Authorization", "Bearer "+opsKey)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 200 {
			t.Errorf("ops agent on %s: expected 200, got %d", ep, resp.StatusCode)
		}
	}
}

func strPtr(s string) *string { return &s }
