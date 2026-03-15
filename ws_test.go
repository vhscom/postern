package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// --- Test helpers ---

func setupWSServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	cfg = &Config{
		Addr:          ":0",
		DBPath:        ":memory:",
		AccessSecret:  "test-access",
		RefreshSecret: "test-refresh",
		AgentSecret:   "test-provisioning-secret",
		CookieSecure:  false,
		Environment:   "development",
	}
	initDB(cfg.DBPath)

	mux := http.NewServeMux()
	mux.Handle("POST /ops/agents", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentCreate)))
	mux.HandleFunc("GET /ops/ws", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			requireAgentKey(http.HandlerFunc(handleOpsWS)).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	apiKey := provisionAgent(t, srv.URL, "ws-test-agent", "write")
	return srv, apiKey
}

func dialWS(t *testing.T, srv *httptest.Server, apiKey string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ops/ws"
	header := http.Header{"Authorization": []string{"Bearer " + apiKey}}
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		body := ""
		if resp != nil {
			b := make([]byte, 512)
			n, _ := resp.Body.Read(b)
			body = string(b[:n])
		}
		t.Fatalf("dial ws: %v %s", err, body)
	}
	return conn
}

func negotiateTestCaps(t *testing.T, conn *websocket.Conn, caps []string) map[string]any {
	t.Helper()
	msg, _ := json.Marshal(map[string]any{
		"type":         "capability.request",
		"capabilities": caps,
	})
	conn.WriteMessage(websocket.TextMessage, msg)

	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read capability.granted: %v", err)
	}
	var resp map[string]any
	json.Unmarshal(raw, &resp)
	if resp["type"] != "capability.granted" {
		t.Fatalf("expected capability.granted, got %v", resp["type"])
	}
	return resp
}

func wsSend(t *testing.T, conn *websocket.Conn, msg map[string]any) {
	t.Helper()
	b, _ := json.Marshal(msg)
	if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
		t.Fatalf("ws send: %v", err)
	}
}

func wsRead(t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	var resp map[string]any
	json.Unmarshal(raw, &resp)
	return resp
}

// --- Pure function tests ---

func TestCheckWSOriginNoOrigin(t *testing.T) {
	cfg = &Config{}
	r := httptest.NewRequest("GET", "/ops/ws", nil)
	if !checkWSOrigin(r) {
		t.Error("non-browser client (no Origin) should be allowed")
	}
}

func TestCheckWSOriginBlockedByDefault(t *testing.T) {
	cfg = &Config{WSAllowedOrigins: ""}
	r := httptest.NewRequest("GET", "/ops/ws", nil)
	r.Header.Set("Origin", "https://evil.com")
	if checkWSOrigin(r) {
		t.Error("browser origins should be blocked when allowlist is empty")
	}
}

func TestCheckWSOriginAllowlisted(t *testing.T) {
	cfg = &Config{WSAllowedOrigins: "https://app.example.com, https://other.com"}
	r := httptest.NewRequest("GET", "/ops/ws", nil)

	r.Header.Set("Origin", "https://app.example.com")
	if !checkWSOrigin(r) {
		t.Error("allowlisted origin should pass")
	}

	r.Header.Set("Origin", "https://other.com")
	if !checkWSOrigin(r) {
		t.Error("second allowlisted origin should pass")
	}

	r.Header.Set("Origin", "https://evil.com")
	if checkWSOrigin(r) {
		t.Error("non-allowlisted origin should be blocked")
	}
}

func TestSubscriptionsStartStop(t *testing.T) {
	s := &subscriptions{active: make(map[string]chan struct{})}

	stop := make(chan struct{})
	s.start("events", stop)
	if len(s.active) != 1 {
		t.Fatalf("expected 1 active sub, got %d", len(s.active))
	}

	// Replace existing
	stop2 := make(chan struct{})
	s.start("events", stop2)
	select {
	case <-stop:
	default:
		t.Error("old channel should be closed on replace")
	}

	if !s.stop("events") {
		t.Error("stop should return true for active sub")
	}
	select {
	case <-stop2:
	default:
		t.Error("channel should be closed on stop")
	}

	if s.stop("events") {
		t.Error("stop should return false for missing sub")
	}
}

func TestSubscriptionsStopAll(t *testing.T) {
	s := &subscriptions{active: make(map[string]chan struct{})}
	ch1 := make(chan struct{})
	ch2 := make(chan struct{})
	s.start("a", ch1)
	s.start("b", ch2)

	s.stopAll()

	select {
	case <-ch1:
	default:
		t.Error("ch1 should be closed")
	}
	select {
	case <-ch2:
	default:
		t.Error("ch2 should be closed")
	}
	if len(s.active) != 0 {
		t.Error("active map should be empty after stopAll")
	}
}

func TestPollNewEvents(t *testing.T) {
	cfg = &Config{AccessSecret: "s", RefreshSecret: "r"}
	initDB(":memory:")

	since := time.Now().UTC().Add(-time.Second).Format("2006-01-02 15:04:05")
	emitEvent("login.success", "1.2.3.4", 1, "ua", 200, nil)
	emitEvent("login.failure", "5.6.7.8", 0, "ua", 401, nil)
	emitEvent("ws.connect", "9.9.9.9", 0, "ua", 101, nil)

	// No filter — all events
	events := pollNewEvents(since, nil)
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}

	// Exact type filter
	events = pollNewEvents(since, []string{"login.success"})
	if len(events) != 1 {
		t.Fatalf("expected 1 event for exact filter, got %d", len(events))
	}

	// Wildcard filter
	events = pollNewEvents(since, []string{"login.*"})
	if len(events) != 2 {
		t.Fatalf("expected 2 events for wildcard filter, got %d", len(events))
	}

	// Non-matching filter
	events = pollNewEvents(since, []string{"registration.*"})
	if len(events) != 0 {
		t.Fatalf("expected 0 events for non-matching filter, got %d", len(events))
	}
}

// --- WebSocket integration tests ---

func TestWSRejectsNoAuth(t *testing.T) {
	cfg = &Config{
		DBPath: ":memory:", AccessSecret: "a", RefreshSecret: "r", AgentSecret: "s",
	}
	initDB(cfg.DBPath)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ops/ws", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			requireAgentKey(http.HandlerFunc(handleOpsWS)).ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ops/ws"
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("expected dial to fail without auth")
	}
	if resp != nil && resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
}

func TestWSRejectsInvalidKey(t *testing.T) {
	cfg = &Config{
		DBPath: ":memory:", AccessSecret: "a", RefreshSecret: "r", AgentSecret: "s",
	}
	initDB(cfg.DBPath)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ops/ws", func(w http.ResponseWriter, r *http.Request) {
		requireAgentKey(http.HandlerFunc(handleOpsWS)).ServeHTTP(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ops/ws"
	header := http.Header{"Authorization": []string{"Bearer bogus-key"}}
	_, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err == nil {
		t.Fatal("expected dial to fail with invalid key")
	}
	if resp != nil && resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestWSCapabilityNegotiation(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()

	resp := negotiateTestCaps(t, conn, []string{"query_events", "query_sessions", "revoke_session", "subscribe_events"})

	granted := resp["granted"].([]any)
	if len(granted) != 4 {
		t.Errorf("expected 4 granted caps, got %d: %v", len(granted), granted)
	}
}

func TestWSCapabilityDeniedForReadTrust(t *testing.T) {
	srv, _ := setupWSServer(t)
	defer srv.Close()

	readKey := provisionAgent(t, srv.URL, "read-agent", "read")
	conn := dialWS(t, srv, readKey)
	defer conn.Close()

	resp := negotiateTestCaps(t, conn, []string{"query_events", "revoke_session"})

	granted := resp["granted"].([]any)
	denied := resp["denied"].([]any)

	grantedSet := map[string]bool{}
	for _, g := range granted {
		grantedSet[g.(string)] = true
	}
	if grantedSet["revoke_session"] {
		t.Error("revoke_session should not be granted to read-trust agent")
	}
	if !grantedSet["query_events"] {
		t.Error("query_events should be granted to read-trust agent")
	}
	if len(denied) == 0 {
		t.Error("expected at least 1 denied capability")
	}
}

func TestWSCapabilityDeniedForNodeAgent(t *testing.T) {
	srv, _ := setupWSServer(t)
	defer srv.Close()

	// Create a user and node to get a node-bound agent
	store.Exec("INSERT INTO account (email, password_data) VALUES ('node-test@test.com', 'hash')")
	var userID int
	store.QueryRow("SELECT id FROM account WHERE email = 'node-test@test.com'").Scan(&userID)

	nodeKey, _, _ := insertNodeWithCredential(store, nodeCreateOpts{
		UserID:         userID,
		Label:          "test-node",
		WGPubkey:       "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		ListenPort:     51820,
		AllowedIPs:     "10.0.0.1/32",
		Keepalive:      25,
		Interface:      "wg0",
		EndpointSource: "stun",
	})

	conn := dialWS(t, srv, nodeKey)
	defer conn.Close()

	resp := negotiateTestCaps(t, conn, []string{"wg_sync", "wg_status", "query_events"})

	grantedSet := map[string]bool{}
	for _, g := range resp["granted"].([]any) {
		grantedSet[g.(string)] = true
	}
	if grantedSet["query_events"] {
		t.Error("ops cap query_events should be denied for node-bound agent")
	}
	if !grantedSet["wg_sync"] {
		t.Error("wg_sync should be granted for node-bound agent")
	}
}

func TestWSBadCapabilityRequest(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()

	// Send wrong message type
	conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"ping"}`))

	// Should get close frame with protocol error
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Fatal("expected connection to close on bad handshake")
	}
	if !websocket.IsCloseError(err, wsProtocolError) {
		t.Errorf("expected close code %d, got %v", wsProtocolError, err)
	}
}

func TestWSPing(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"query_events"})

	wsSend(t, conn, map[string]any{"type": "ping", "id": "test-123"})
	resp := wsRead(t, conn)

	if resp["type"] != "pong" {
		t.Errorf("expected pong, got %v", resp["type"])
	}
	if resp["id"] != "test-123" {
		t.Errorf("expected id test-123, got %v", resp["id"])
	}
}

func TestWSPingNoID(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"query_events"})

	wsSend(t, conn, map[string]any{"type": "ping"})
	resp := wsRead(t, conn)

	if resp["type"] != "pong" {
		t.Errorf("expected pong, got %v", resp["type"])
	}
	if _, ok := resp["id"]; ok {
		t.Error("pong should not have id when ping has no id")
	}
}

func TestWSUnknownType(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"query_events"})

	wsSend(t, conn, map[string]any{"type": "bogus", "id": "x"})
	resp := wsRead(t, conn)

	if resp["type"] != "error" {
		t.Errorf("expected error, got %v", resp["type"])
	}
	if resp["code"] != "UNKNOWN_TYPE" {
		t.Errorf("expected UNKNOWN_TYPE, got %v", resp["code"])
	}
}

func TestWSNotGrantedCapability(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	// Only negotiate query_events — not revoke_session
	negotiateTestCaps(t, conn, []string{"query_events"})

	wsSend(t, conn, map[string]any{"type": "revoke_session", "id": "r1"})
	resp := wsRead(t, conn)

	if resp["code"] != "NOT_GRANTED" {
		t.Errorf("expected NOT_GRANTED, got %v", resp["code"])
	}
}

func TestWSParseError(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"query_events"})

	conn.WriteMessage(websocket.TextMessage, []byte("not json"))
	resp := wsRead(t, conn)

	if resp["code"] != "PARSE_ERROR" {
		t.Errorf("expected PARSE_ERROR, got %v", resp["code"])
	}
}

func TestWSQueryEvents(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	emitEvent("test.ws.query", "1.2.3.4", 0, "ua", 200, nil)

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"query_events"})

	wsSend(t, conn, map[string]any{
		"type": "query_events",
		"id":   "q1",
		"payload": map[string]any{
			"since": "1h",
			"limit": 10,
		},
	})
	resp := wsRead(t, conn)

	if resp["type"] != "query_events.result" {
		t.Fatalf("expected query_events.result, got %v", resp["type"])
	}
	if resp["id"] != "q1" {
		t.Errorf("expected id q1, got %v", resp["id"])
	}
	payload := resp["payload"].(map[string]any)
	events := payload["events"].([]any)
	if len(events) == 0 {
		t.Error("expected at least 1 event")
	}
}

func TestWSQueryEventsAggregate(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	emitEvent("login.success", "1.1.1.1", 1, "ua", 200, nil)
	emitEvent("login.failure", "2.2.2.2", 0, "ua", 401, nil)
	emitEvent("login.failure", "3.3.3.3", 0, "ua", 401, nil)

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"query_events"})

	wsSend(t, conn, map[string]any{
		"type": "query_events",
		"id":   "q2",
		"payload": map[string]any{
			"since":     "1h",
			"aggregate": true,
		},
	})
	resp := wsRead(t, conn)

	payload := resp["payload"].(map[string]any)
	stats := payload["stats"].(map[string]any)
	if stats["login.failure"] == nil {
		t.Error("expected login.failure in stats")
	}
}

func TestWSQuerySessions(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	// Create account and session
	store.Exec("INSERT INTO account (email, password_data) VALUES ('ws-sess@test.com', 'hash')")
	var uid int
	store.QueryRow("SELECT id FROM account WHERE email = 'ws-sess@test.com'").Scan(&uid)
	createSession(uid, "test-ua", "127.0.0.1")

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"query_sessions"})

	wsSend(t, conn, map[string]any{
		"type": "query_sessions",
		"id":   "s1",
		"payload": map[string]any{
			"active": true,
		},
	})
	resp := wsRead(t, conn)

	if resp["type"] != "query_sessions.result" {
		t.Fatalf("expected query_sessions.result, got %v", resp["type"])
	}
	payload := resp["payload"].(map[string]any)
	sessions := payload["sessions"].([]any)
	if len(sessions) == 0 {
		t.Error("expected at least 1 session")
	}
}

func TestWSRevokeSessionAll(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	store.Exec("INSERT INTO account (email, password_data) VALUES ('ws-rev@test.com', 'hash')")
	var uid int
	store.QueryRow("SELECT id FROM account WHERE email = 'ws-rev@test.com'").Scan(&uid)
	createSession(uid, "ua", "127.0.0.1")
	createSession(uid, "ua2", "127.0.0.2")

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"revoke_session"})

	wsSend(t, conn, map[string]any{
		"type": "revoke_session",
		"id":   "rev1",
		"payload": map[string]any{
			"scope": "all",
		},
	})
	resp := wsRead(t, conn)

	if resp["type"] != "revoke_session.result" {
		t.Fatalf("expected revoke_session.result, got %v", resp["type"])
	}
	payload := resp["payload"].(map[string]any)
	revoked := payload["revoked"].(float64)
	if revoked < 2 {
		t.Errorf("expected at least 2 revoked, got %v", revoked)
	}
}

func TestWSRevokeSessionBadScope(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"revoke_session"})

	wsSend(t, conn, map[string]any{
		"type": "revoke_session",
		"id":   "rev2",
		"payload": map[string]any{
			"scope": "invalid",
		},
	})
	resp := wsRead(t, conn)

	if resp["code"] != "INVALID_SCOPE" {
		t.Errorf("expected INVALID_SCOPE, got %v", resp["code"])
	}
}

func TestWSSubscribeAndReceive(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"subscribe_events"})

	// Use a unique event type to avoid interference from other tests
	wsSend(t, conn, map[string]any{
		"type": "subscribe_events",
		"id":   "sub1",
		"payload": map[string]any{
			"types": []string{"test.subscribe.receive"},
		},
	})
	ack := wsRead(t, conn)
	if ack["type"] != "subscribe_events.result" {
		t.Fatalf("expected subscribe_events.result, got %v", ack["type"])
	}

	// Emit multiple times to ensure the subscription goroutine catches a broadcast
	go func() {
		for range 5 {
			time.Sleep(200 * time.Millisecond)
			emitEvent("test.subscribe.receive", "1.2.3.4", 0, "ua", 200, nil)
		}
	}()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("timed out waiting for event: %v", err)
		}
		var resp map[string]any
		json.Unmarshal(raw, &resp)
		if resp["type"] == "event" {
			payload := resp["payload"].(map[string]any)
			if payload["event_type"] != "test.subscribe.receive" {
				t.Errorf("expected test.subscribe.receive, got %v", payload["event_type"])
			}
			return
		}
	}
}

func TestWSSubscribeWithTypeFilter(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"subscribe_events"})

	wsSend(t, conn, map[string]any{
		"type": "subscribe_events",
		"id":   "sub2",
		"payload": map[string]any{
			"types": []string{"test.filtered.*"},
		},
	})
	ack := wsRead(t, conn)
	if ack["type"] != "subscribe_events.result" {
		t.Fatalf("expected ack, got %v", ack["type"])
	}

	// Emit multiple times with delays to ensure the subscription goroutine
	// catches at least one broadcast signal while it's waiting
	go func() {
		for range 5 {
			time.Sleep(200 * time.Millisecond)
			emitEvent("test.filtered.match", "2.2.2.2", 1, "ua", 200, nil)
		}
	}()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("timed out waiting for filtered event: %v", err)
		}
		var resp map[string]any
		json.Unmarshal(raw, &resp)
		if resp["type"] == "event" {
			payload := resp["payload"].(map[string]any)
			if payload["event_type"] != "test.filtered.match" {
				t.Errorf("expected test.filtered.match, got %v", payload["event_type"])
			}
			return
		}
	}
}

func TestWSUnsubscribe(t *testing.T) {
	srv, apiKey := setupWSServer(t)
	defer srv.Close()

	conn := dialWS(t, srv, apiKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"subscribe_events"})

	wsSend(t, conn, map[string]any{"type": "subscribe_events", "id": "sub3"})
	wsRead(t, conn) // ack

	wsSend(t, conn, map[string]any{"type": "unsubscribe_events", "id": "unsub1"})
	resp := wsRead(t, conn)

	if resp["type"] != "unsubscribe_events.result" {
		t.Fatalf("expected unsubscribe_events.result, got %v", resp["type"])
	}
	payload := resp["payload"].(map[string]any)
	if payload["unsubscribed"] != true {
		t.Error("expected unsubscribed: true")
	}
}

func TestWSEndpointDiscovered(t *testing.T) {
	srv, _ := setupWSServer(t)
	defer srv.Close()

	store.Exec("INSERT INTO account (email, password_data) VALUES ('ep-test@test.com', 'hash')")
	var userID int
	store.QueryRow("SELECT id FROM account WHERE email = 'ep-test@test.com'").Scan(&userID)

	nodeKey, _, _ := insertNodeWithCredential(store, nodeCreateOpts{
		UserID:         userID,
		Label:          "ep-node",
		WGPubkey:       "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		ListenPort:     51820,
		AllowedIPs:     "10.0.0.1/32",
		Keepalive:      25,
		Interface:      "wg0",
		EndpointSource: "stun",
	})

	conn := dialWS(t, srv, nodeKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"wg_sync", "endpoint_discovery"})

	// May receive a wg.sync message first — drain it
	go func() { time.Sleep(200 * time.Millisecond) }()

	wsSend(t, conn, map[string]any{
		"type": "endpoint.discovered",
		"id":   "ep1",
		"payload": map[string]any{
			"endpoint": "203.0.113.5:51820",
		},
	})

	// Read messages until we get our result
	for i := 0; i < 5; i++ {
		resp := wsRead(t, conn)
		if resp["type"] == "endpoint.discovered.result" {
			payload := resp["payload"].(map[string]any)
			if payload["updated"] != true {
				t.Error("expected updated: true")
			}
			return
		}
	}
	t.Fatal("did not receive endpoint.discovered.result")
}

func TestWSEndpointDiscoveredInvalid(t *testing.T) {
	srv, _ := setupWSServer(t)
	defer srv.Close()

	store.Exec("INSERT INTO account (email, password_data) VALUES ('ep2@test.com', 'hash')")
	var userID int
	store.QueryRow("SELECT id FROM account WHERE email = 'ep2@test.com'").Scan(&userID)

	nodeKey, _, _ := insertNodeWithCredential(store, nodeCreateOpts{
		UserID: userID, Label: "ep2-node",
		WGPubkey:       "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		ListenPort:     51820,
		AllowedIPs:     "10.0.0.2/32",
		Keepalive:      25,
		Interface:      "wg0",
		EndpointSource: "stun",
	})

	conn := dialWS(t, srv, nodeKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"wg_sync", "endpoint_discovery"})

	wsSend(t, conn, map[string]any{
		"type": "endpoint.discovered",
		"id":   "ep2",
		"payload": map[string]any{
			"endpoint": "not-valid",
		},
	})

	for i := 0; i < 5; i++ {
		resp := wsRead(t, conn)
		if resp["type"] == "error" {
			if resp["code"] != "VALIDATION_ERROR" {
				t.Errorf("expected VALIDATION_ERROR, got %v", resp["code"])
			}
			return
		}
	}
	t.Fatal("did not receive VALIDATION_ERROR")
}

func TestWSKeyRotate(t *testing.T) {
	srv, _ := setupWSServer(t)
	defer srv.Close()

	store.Exec("INSERT INTO account (email, password_data) VALUES ('kr@test.com', 'hash')")
	var userID int
	store.QueryRow("SELECT id FROM account WHERE email = 'kr@test.com'").Scan(&userID)

	nodeKey, _, _ := insertNodeWithCredential(store, nodeCreateOpts{
		UserID: userID, Label: "kr-node",
		WGPubkey:       "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		ListenPort:     51820,
		AllowedIPs:     "10.0.0.3/32",
		Keepalive:      25,
		Interface:      "wg0",
		EndpointSource: "stun",
	})

	conn := dialWS(t, srv, nodeKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"wg_sync", "key_rotate"})

	newPubkey := "dGVzdG5ld2tleXRlc3RuZXdrZXl0ZXN0bmV3a2V5cXI="
	wsSend(t, conn, map[string]any{
		"type": "key.rotate",
		"id":   "kr1",
		"payload": map[string]any{
			"public_key": newPubkey,
		},
	})

	for i := 0; i < 5; i++ {
		resp := wsRead(t, conn)
		if resp["type"] == "key.rotate.result" {
			payload := resp["payload"].(map[string]any)
			if payload["success"] != true {
				t.Error("expected success: true")
			}
			// Verify DB updated
			var stored string
			store.QueryRow("SELECT wg_pubkey FROM user_node WHERE label = 'kr-node'").Scan(&stored)
			if stored != newPubkey {
				t.Errorf("expected pubkey %s in DB, got %s", newPubkey, stored)
			}
			return
		}
	}
	t.Fatal("did not receive key.rotate.result")
}

func TestWSKeyRotateInvalidPubkey(t *testing.T) {
	srv, _ := setupWSServer(t)
	defer srv.Close()

	store.Exec("INSERT INTO account (email, password_data) VALUES ('kr2@test.com', 'hash')")
	var userID int
	store.QueryRow("SELECT id FROM account WHERE email = 'kr2@test.com'").Scan(&userID)

	nodeKey, _, _ := insertNodeWithCredential(store, nodeCreateOpts{
		UserID: userID, Label: "kr2-node",
		WGPubkey:       "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=",
		ListenPort:     51820,
		AllowedIPs:     "10.0.0.4/32",
		Keepalive:      25,
		Interface:      "wg0",
		EndpointSource: "stun",
	})

	conn := dialWS(t, srv, nodeKey)
	defer conn.Close()
	negotiateTestCaps(t, conn, []string{"wg_sync", "key_rotate"})

	wsSend(t, conn, map[string]any{
		"type": "key.rotate",
		"id":   "kr2",
		"payload": map[string]any{
			"public_key": "not-base64",
		},
	})

	for i := 0; i < 5; i++ {
		resp := wsRead(t, conn)
		if resp["type"] == "error" {
			if resp["code"] != "VALIDATION_ERROR" {
				t.Errorf("expected VALIDATION_ERROR, got %v", resp["code"])
			}
			return
		}
	}
	t.Fatal("did not receive VALIDATION_ERROR")
}
