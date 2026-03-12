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
