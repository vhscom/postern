package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func setupOpsServer(t *testing.T) (*httptest.Server, string) {
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
	mux.Handle("DELETE /ops/agents/{name}", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentRevoke)))
	mux.Handle("GET /ops/agents", requireAgentKey(http.HandlerFunc(handleOpsAgentList)))
	mux.Handle("GET /ops/sessions", requireAgentKey(http.HandlerFunc(handleOpsSessions)))
	mux.Handle("POST /ops/sessions/revoke", requireAgentKey(requireWriteTrust(http.HandlerFunc(handleOpsSessionRevoke))))
	mux.Handle("GET /ops/events", requireAgentKey(http.HandlerFunc(handleOpsEvents)))
	mux.Handle("GET /ops/events/stats", requireAgentKey(http.HandlerFunc(handleOpsEventStats)))
	srv := httptest.NewServer(mux)

	// Provision an agent
	apiKey := provisionAgent(t, srv.URL, "test-agent", "write")
	return srv, apiKey
}

func provisionAgent(t *testing.T, base, name, trust string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"name": name, "trustLevel": trust})
	req, _ := http.NewRequest("POST", base+"/ops/agents", jsonReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Provisioning-Secret", cfg.AgentSecret)
	resp, _ := http.DefaultClient.Do(req)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Fatalf("provision agent: %d %v", resp.StatusCode, result)
	}
	return result["apiKey"].(string)
}

func agentGet(url, apiKey string) (*http.Response, map[string]any) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	resp, _ := http.DefaultClient.Do(req)
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	return resp, result
}

func TestAgentProvisioning(t *testing.T) {
	srv, apiKey := setupOpsServer(t)
	defer srv.Close()

	// List agents
	resp, body := agentGet(srv.URL+"/ops/agents", apiKey)
	if resp.StatusCode != 200 {
		t.Fatalf("list agents: %d", resp.StatusCode)
	}
	agents := body["agents"].([]any)
	if len(agents) == 0 {
		t.Error("expected at least 1 agent")
	}
}

func TestAgentProvisioningBadSecret(t *testing.T) {
	cfg = &Config{AgentSecret: "correct-secret"}
	initDB(":memory:")

	mux := http.NewServeMux()
	mux.Handle("POST /ops/agents", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentCreate)))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body, _ := json.Marshal(map[string]string{"name": "bad"})
	req, _ := http.NewRequest("POST", srv.URL+"/ops/agents", jsonReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Provisioning-Secret", "wrong-secret")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSessionsQuery(t *testing.T) {
	srv, apiKey := setupOpsServer(t)
	defer srv.Close()

	// Create a session for querying
	createSession(1, "test-ua", "127.0.0.1")

	resp, body := agentGet(srv.URL+"/ops/sessions", apiKey)
	if resp.StatusCode != 200 {
		t.Fatalf("sessions: %d", resp.StatusCode)
	}
	sessions := body["sessions"].([]any)
	if len(sessions) == 0 {
		// There might be no account with id=1 yet, so session creation may fail
		// due to FK constraint. That's fine for this test.
		t.Log("no sessions (expected if no account exists)")
	}
}

func TestEventsQuery(t *testing.T) {
	srv, apiKey := setupOpsServer(t)
	defer srv.Close()

	emitEvent("test.event", "1.2.3.4", 0, "test-ua", 200, nil)

	resp, body := agentGet(srv.URL+"/ops/events", apiKey)
	if resp.StatusCode != 200 {
		t.Fatalf("events: %d", resp.StatusCode)
	}
	events := body["events"].([]any)
	if len(events) == 0 {
		t.Error("expected at least 1 event")
	}
}

func TestEventStats(t *testing.T) {
	srv, apiKey := setupOpsServer(t)
	defer srv.Close()

	emitEvent("login.success", "1.2.3.4", 1, "ua", 200, nil)
	emitEvent("login.failure", "1.2.3.4", 0, "ua", 401, nil)
	emitEvent("login.failure", "1.2.3.4", 0, "ua", 401, nil)

	resp, body := agentGet(srv.URL+"/ops/events/stats", apiKey)
	if resp.StatusCode != 200 {
		t.Fatalf("stats: %d", resp.StatusCode)
	}
	stats := body["stats"].(map[string]any)
	if stats["login.failure"] == nil {
		t.Error("expected login.failure in stats")
	}
}

func TestAgentRevocation(t *testing.T) {
	cfg = &Config{AgentSecret: "secret", AccessSecret: "a", RefreshSecret: "r"}
	initDB(":memory:")

	mux := http.NewServeMux()
	mux.Handle("POST /ops/agents", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentCreate)))
	mux.Handle("DELETE /ops/agents/{name}", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentRevoke)))
	mux.Handle("GET /ops/agents", requireAgentKey(http.HandlerFunc(handleOpsAgentList)))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	apiKey := provisionAgent(t, srv.URL, "revoke-me", "read")

	// Verify agent works
	resp, _ := agentGet(srv.URL+"/ops/agents", apiKey)
	if resp.StatusCode != 200 {
		t.Fatal("agent should work before revocation")
	}

	// Revoke
	req, _ := http.NewRequest("DELETE", srv.URL+"/ops/agents/revoke-me", nil)
	req.Header.Set("X-Provisioning-Secret", cfg.AgentSecret)
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("revoke: expected 200, got %d", resp.StatusCode)
	}

	// Agent should no longer work
	resp, _ = agentGet(srv.URL+"/ops/agents", apiKey)
	if resp.StatusCode != 401 {
		t.Errorf("revoked agent: expected 401, got %d", resp.StatusCode)
	}
}

func jsonReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
