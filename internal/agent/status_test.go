package agent

import (
	"strings"
	"testing"
)

func TestNewAgentStatus(t *testing.T) {
	s := newAgentStatus("https://example.com", "wg0")
	if s.server != "https://example.com" {
		t.Errorf("server = %q, want %q", s.server, "https://example.com")
	}
	if s.iface != "wg0" {
		t.Errorf("iface = %q, want %q", s.iface, "wg0")
	}
	if s.state != "connecting" {
		t.Errorf("state = %q, want %q", s.state, "connecting")
	}
}

func TestStatusTransitions(t *testing.T) {
	s := newAgentStatus("srv", "wg0")

	s.setConnected()
	if s.state != "connected" {
		t.Errorf("after setConnected: state = %q", s.state)
	}
	if s.lastError != "" {
		t.Error("setConnected should clear lastError")
	}

	s.setSyncing()
	if s.state != "syncing" {
		t.Errorf("after setSyncing: state = %q", s.state)
	}

	s.setReady(3)
	if s.state != "ready" || s.peers != 3 {
		t.Errorf("after setReady: state=%q peers=%d", s.state, s.peers)
	}

	s.setReconnecting("timeout")
	if s.state != "reconnecting" || s.lastError != "timeout" {
		t.Errorf("after setReconnecting: state=%q lastError=%q", s.state, s.lastError)
	}
}

func TestStatusSetters(t *testing.T) {
	s := newAgentStatus("srv", "wg0")

	s.setMeshIP("10.0.0.1/32")
	if s.meshIP != "10.0.0.1/32" {
		t.Errorf("meshIP = %q", s.meshIP)
	}

	s.setIface("utun6")
	if s.iface != "utun6" {
		t.Errorf("iface = %q", s.iface)
	}

	s.setEndpoint("1.2.3.4:51820")
	if s.endpoint != "1.2.3.4:51820" {
		t.Errorf("endpoint = %q", s.endpoint)
	}

	s.setPeers(5)
	if s.peers != 5 {
		t.Errorf("peers = %d", s.peers)
	}
}

func TestEventRolling(t *testing.T) {
	s := newAgentStatus("srv", "wg0")
	for i := 0; i < 20; i++ {
		s.logEvent("event")
	}
	if len(s.events) != maxEvents {
		t.Errorf("events length = %d, want %d", len(s.events), maxEvents)
	}
}

func TestLogSync(t *testing.T) {
	s := newAgentStatus("srv", "wg0")

	s.logSync("full_sync", nil)
	if s.events[0] != "sync full_sync" {
		t.Errorf("event = %q", s.events[0])
	}

	s.logSync("add_peer", errorf("fail"))
	if !strings.Contains(s.events[1], "failed") {
		t.Errorf("event = %q, want 'failed' substring", s.events[1])
	}
}

func TestLogError(t *testing.T) {
	s := newAgentStatus("srv", "wg0")
	s.logError("something broke")
	if s.lastError != "something broke" {
		t.Errorf("lastError = %q", s.lastError)
	}
	if len(s.events) != 1 || s.events[0] != "something broke" {
		t.Error("logError should also add to events")
	}
}

func TestRenderDedup(t *testing.T) {
	s := newAgentStatus("srv", "wg0")
	s.render()
	first := s.lastOut

	// Second render with no state change should be a no-op
	s.render()
	if s.lastOut != first {
		t.Error("duplicate render should not change lastOut")
	}

	// State change should produce new output
	s.setConnected()
	s.render()
	if s.lastOut == first {
		t.Error("render after state change should produce new output")
	}
}

func TestRenderContainsFields(t *testing.T) {
	s := newAgentStatus("https://mesh.example.com", "utun3")
	s.setConnected()
	s.setMeshIP("10.0.0.1/32")
	s.setEndpoint("1.2.3.4:51820")
	s.setReady(2)
	s.render()

	for _, want := range []string{"mesh.example.com", "utun3", "10.0.0.1/32", "1.2.3.4:51820", "2 synced"} {
		if !strings.Contains(s.lastOut, want) {
			t.Errorf("render output missing %q", want)
		}
	}
}

func TestRenderHintOnce(t *testing.T) {
	s := newAgentStatus("srv", "wg0")
	s.setReady(0)
	s.render()
	if !strings.Contains(s.lastOut, "postern agent install") {
		t.Error("first ready render should show install hint")
	}
	if !s.hinted {
		t.Error("hinted should be true after first ready render")
	}

	// Change state to force new render
	s.logEvent("something")
	s.render()
	// The hint should not appear again (hinted is true)
	count := strings.Count(s.lastOut, "postern agent install")
	if count > 1 {
		t.Errorf("hint appeared %d times, want at most 1", count)
	}
}

// errorf is a helper to create an error for testing.
type testError string

func (e testError) Error() string { return string(e) }
func errorf(s string) error       { return testError(s) }
