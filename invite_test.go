package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupInviteServer(t *testing.T) (*httptest.Server, []*http.Cookie) {
	t.Helper()

	cfg = &Config{
		Addr:          ":0",
		DBPath:        ":memory:",
		AccessSecret:  "test-access",
		RefreshSecret: "test-refresh",
		CookieSecure:  false,
		Environment:   "development",
		BaseURL:       "http://localhost:8080",
	}
	initDB(cfg.DBPath)

	mux := http.NewServeMux()
	mux.Handle("POST /auth/register", http.HandlerFunc(handleRegister))
	mux.Handle("POST /auth/login", http.HandlerFunc(handleLogin))
	mux.Handle("POST /account/nodes", requireAuthMiddleware(http.HandlerFunc(handleNodeCreate)))
	mux.Handle("POST /account/nodes/invite", requireAuthMiddleware(http.HandlerFunc(handleInviteCreate)))
	mux.Handle("POST /join", http.HandlerFunc(handleJoinRedeem))
	mux.Handle("GET /account/nodes", requireAuthMiddleware(http.HandlerFunc(handleNodeList)))
	srv := httptest.NewServer(mux)

	jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "invite@test.com", "password": "password123",
	}, nil)
	resp, _ := jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "invite@test.com", "password": "password123",
	}, nil)

	return srv, resp.Cookies()
}

func TestInviteCreate(t *testing.T) {
	srv, cookies := setupInviteServer(t)
	defer srv.Close()

	resp, body := jsonPost(srv.URL+"/account/nodes/invite", map[string]any{}, cookies)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d: %v", resp.StatusCode, body)
	}
	if body["token"] == nil || body["token"] == "" {
		t.Error("expected token in response")
	}
	if body["join_command"] == nil {
		t.Error("expected join_command in response")
	}
}

func TestJoinRedeem(t *testing.T) {
	srv, cookies := setupInviteServer(t)
	defer srv.Close()

	// Create invite
	_, inviteBody := jsonPost(srv.URL+"/account/nodes/invite", map[string]any{}, cookies)
	token := inviteBody["token"].(string)

	// Redeem — no auth needed
	resp, body := jsonPost(srv.URL+"/join", map[string]string{
		"token":     token,
		"label":     "laptop",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d: %v", resp.StatusCode, body)
	}
	if body["api_key"] == nil || body["api_key"] == "" {
		t.Error("expected api_key in response")
	}
	if body["mesh_ip"] == nil || body["mesh_ip"] == "" {
		t.Error("expected mesh_ip in response")
	}
	if body["label"] != "laptop" {
		t.Errorf("expected label 'laptop', got %v", body["label"])
	}

	// Verify node shows in list
	_, listBody := jsonGet(srv.URL+"/account/nodes", cookies)
	nodes := listBody["nodes"].([]any)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	node := nodes[0].(map[string]any)
	if node["label"] != "laptop" {
		t.Errorf("expected node label 'laptop', got %v", node["label"])
	}
}

func TestJoinRedeemTokenReuse(t *testing.T) {
	srv, cookies := setupInviteServer(t)
	defer srv.Close()

	_, inviteBody := jsonPost(srv.URL+"/account/nodes/invite", map[string]any{}, cookies)
	token := inviteBody["token"].(string)

	// First use
	resp, _ := jsonPost(srv.URL+"/join", map[string]string{
		"token": token, "label": "first", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("first use: expected 201, got %d", resp.StatusCode)
	}

	// Second use — should fail
	resp, body := jsonPost(srv.URL+"/join", map[string]string{
		"token": token, "label": "second", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, nil)
	if resp.StatusCode != 409 {
		t.Fatalf("reuse: expected 409, got %d: %v", resp.StatusCode, body)
	}
}

func TestJoinRedeemInvalidToken(t *testing.T) {
	srv, _ := setupInviteServer(t)
	defer srv.Close()

	resp, _ := jsonPost(srv.URL+"/join", map[string]string{
		"token": "bogus", "label": "nope", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestJoinRedeemTierLimit(t *testing.T) {
	srv, cookies := setupInviteServer(t)
	defer srv.Close()

	// Fill up free tier (2 nodes)
	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "n1", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.1/32",
	}, cookies)
	jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label": "n2", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
		"allowed_ips": "10.0.0.2/32",
	}, cookies)

	// Create invite — should succeed
	_, inviteBody := jsonPost(srv.URL+"/account/nodes/invite", map[string]any{}, cookies)
	token := inviteBody["token"].(string)

	// Redeem — should fail (tier limit)
	resp, _ := jsonPost(srv.URL+"/join", map[string]string{
		"token": token, "label": "n3", "wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, nil)
	if resp.StatusCode != 402 {
		t.Fatalf("expected 402 for tier limit, got %d", resp.StatusCode)
	}
}

func TestAllocateMeshIP(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")

	// First allocation should be 10.0.0.1/32
	ip, err := allocateMeshIP(store, 1)
	if err != nil {
		t.Fatalf("allocateMeshIP: %v", err)
	}
	if ip != "10.0.0.1/32" {
		t.Errorf("expected 10.0.0.1/32, got %s", ip)
	}

	// Add a node with that IP
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('a1', 'h', 'read', 1)")
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'n1', 'pk', '10.0.0.1/32', 1, 'manual')`)

	// Second allocation should be 10.0.0.2/32
	ip, err = allocateMeshIP(store, 1)
	if err != nil {
		t.Fatalf("allocateMeshIP: %v", err)
	}
	if ip != "10.0.0.2/32" {
		t.Errorf("expected 10.0.0.2/32, got %s", ip)
	}
}

func TestNodeCreateAutoIP(t *testing.T) {
	srv, cookies := setupInviteServer(t)
	defer srv.Close()

	// Create node without allowed_ips — should auto-assign
	resp, body := jsonPost(srv.URL+"/account/nodes", map[string]string{
		"label":     "auto-ip",
		"wg_pubkey": "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
	}, cookies)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201, got %d: %v", resp.StatusCode, body)
	}
	if body["mesh_ip"] == nil || body["mesh_ip"] == "" {
		t.Error("expected mesh_ip in response")
	}
	if body["mesh_ip"] != "10.0.0.1/32" {
		t.Errorf("expected auto-assigned 10.0.0.1/32, got %v", body["mesh_ip"])
	}
}

func TestInviteTableExists(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	var name string
	err := store.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='invite_token'").Scan(&name)
	if err != nil {
		t.Fatal("invite_token table should exist")
	}
}

func TestNodeSyncIncludesLabelAndSelf(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('agent1', 'h1', 'read', 1)")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('agent2', 'h2', 'read', 1)")
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, wg_listen_port, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'gateway', 'pubkey1', '10.0.0.1/32', 51820, 1, 'manual')`)
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, allowed_ips, wg_listen_port, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'laptop', 'pubkey2', '10.0.0.2/32', 51821, 2, 'stun')`)

	// Verify the query used by notifyNodeSync fetches label and listen_port
	rows, err := store.Query(
		"SELECT id, label, wg_pubkey, wg_endpoint, allowed_ips, wg_listen_port, persistent_keepalive FROM user_node WHERE user_id = ?",
		1,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type meshNode struct {
		ID, ListenPort, Keepalive int
		Label, Pubkey, AllowedIPs string
		Endpoint                  *string
	}
	var nodes []meshNode
	for rows.Next() {
		var n meshNode
		rows.Scan(&n.ID, &n.Label, &n.Pubkey, &n.Endpoint, &n.AllowedIPs, &n.ListenPort, &n.Keepalive)
		nodes = append(nodes, n)
	}

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Label != "gateway" {
		t.Errorf("expected label 'gateway', got %q", nodes[0].Label)
	}
	if nodes[1].ListenPort != 51821 {
		t.Errorf("expected listen port 51821, got %d", nodes[1].ListenPort)
	}
}
