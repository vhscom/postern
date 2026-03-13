package main

import (
	"testing"
)

func TestCapsByTrustIncludesNewCapabilities(t *testing.T) {
	for _, level := range []string{"read", "write"} {
		caps := capsByTrust[level]
		for _, cap := range []string{"endpoint_discovery", "key_rotate"} {
			if !caps[cap] {
				t.Errorf("trust level %q should include %q capability", level, cap)
			}
		}
	}
}

func TestLookupNodeForAgentNotFound(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	nid, uid := lookupNodeForAgent(999)
	if nid != 0 || uid != 0 {
		t.Errorf("expected 0/0 for unknown agent, got %d/%d", nid, uid)
	}
}

func TestValidEndpointRejectsInvalid(t *testing.T) {
	bad := []string{"no-port", "", "just-host", ":::"}
	for _, ep := range bad {
		if validEndpoint(ep) {
			t.Errorf("validEndpoint(%q) should be false", ep)
		}
	}
	good := []string{"1.2.3.4:51820", "[::1]:51820", "example.com:51820"}
	for _, ep := range good {
		if !validEndpoint(ep) {
			t.Errorf("validEndpoint(%q) should be true", ep)
		}
	}
}

func TestValidWGPubkeyRejectsInvalid(t *testing.T) {
	bad := []string{"tooshort", "", "not-base64!!!", "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg"}
	for _, k := range bad {
		if validWGPubkey(k) {
			t.Errorf("validWGPubkey(%q) should be false", k)
		}
	}
	if !validWGPubkey("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=") {
		t.Error("valid pubkey rejected")
	}
}

func TestValidAllowedIPs(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"10.0.0.1/32", true},
		{"192.168.1.0/24", true},
		{"fd00::1/128", true},
		{"0.0.0.0/0", true},
		{"10.0.0.1", false},
		{"not-cidr", false},
		{"", false},
		{"10.0.0.1/32\n127.0.0.1 evil.com", false},
		{"10.0.0.1/32\nevil", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := validAllowedIPs(tt.input); got != tt.valid {
				t.Errorf("validAllowedIPs(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
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

func TestEndpointSourcePreservation(t *testing.T) {
	cfg = &Config{DBPath: ":memory:"}
	initDB(cfg.DBPath)

	store.Exec("INSERT INTO account (email, password_data) VALUES ('test@test.com', 'x')")
	store.Exec("INSERT INTO agent_credential (name, key_hash, trust_level, user_id) VALUES ('a1', 'h', 'read', 1)")

	// Create node with manual endpoint
	store.Exec(`INSERT INTO user_node (user_id, label, wg_pubkey, wg_endpoint, allowed_ips, agent_credential_id, wg_endpoint_source)
		VALUES (1, 'n1', 'pk', '1.2.3.4:51820', '10.0.0.1/32', 1, 'manual')`)

	// Try STUN update — should not affect manual endpoint
	result, _ := store.Exec(
		"UPDATE user_node SET wg_endpoint = ?, wg_endpoint_source = 'stun' WHERE id = 1 AND wg_endpoint_source != 'manual'",
		"5.6.7.8:51820",
	)
	rows, _ := result.RowsAffected()
	if rows != 0 {
		t.Error("STUN should not overwrite manual endpoint")
	}

	// Verify original endpoint preserved
	var ep string
	store.QueryRow("SELECT wg_endpoint FROM user_node WHERE id = 1").Scan(&ep)
	if ep != "1.2.3.4:51820" {
		t.Errorf("endpoint should be preserved, got %s", ep)
	}
}
