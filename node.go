package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	maxNodesFree = 2
	maxNodesPro  = 10
	maxNodesTeam = 25
)

func nodeLimit(tier string) int {
	switch tier {
	case "pro":
		return maxNodesPro
	case "team":
		return maxNodesTeam
	default:
		return maxNodesFree
	}
}

// GET /account/nodes
func handleNodeList(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tier := getUserTier(claims.UID)

	rows, err := store.Query(
		`SELECT n.label, n.wg_pubkey, n.wg_endpoint, n.wg_listen_port, n.interface_name,
			n.last_seen_at, n.created_at, n.updated_at
		FROM user_node n WHERE n.user_id = ? ORDER BY n.created_at`,
		claims.UID,
	)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch nodes")
		return
	}
	defer rows.Close()

	type node struct {
		Label      string  `json:"label"`
		WGPubkey   string  `json:"wg_pubkey"`
		WGEndpoint *string `json:"wg_endpoint"`
		ListenPort int     `json:"wg_listen_port"`
		Interface  string  `json:"interface_name"`
		LastSeenAt *string `json:"last_seen_at"`
		CreatedAt  string  `json:"created_at"`
		UpdatedAt  string  `json:"updated_at"`
	}
	var nodes []node
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.Label, &n.WGPubkey, &n.WGEndpoint, &n.ListenPort, &n.Interface,
			&n.LastSeenAt, &n.CreatedAt, &n.UpdatedAt); err != nil {
			continue
		}
		nodes = append(nodes, n)
	}
	if nodes == nil {
		nodes = []node{}
	}
	jsonOK(w, map[string]any{
		"nodes": nodes,
		"tier":  tier,
		"limit": nodeLimit(tier),
	})
}

// POST /account/nodes
func handleNodeCreate(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	var body struct {
		Label      string `json:"label"`
		WGPubkey   string `json:"wg_pubkey"`
		WGEndpoint string `json:"wg_endpoint"`
		ListenPort int    `json:"wg_listen_port"`
		Interface  string `json:"interface_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	body.Label = strings.TrimSpace(body.Label)
	if body.Label == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Label required")
		return
	}
	if !validLabel(body.Label) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid label (alphanumeric, hyphens, max 32 chars)")
		return
	}
	body.WGPubkey = strings.TrimSpace(body.WGPubkey)
	if !validWGPubkey(body.WGPubkey) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid WireGuard public key")
		return
	}
	if body.ListenPort == 0 {
		body.ListenPort = 51820
	}
	if body.Interface == "" {
		body.Interface = "wg0"
	}

	// Tier limit
	tier := getUserTier(claims.UID)
	limit := nodeLimit(tier)
	var count int
	store.QueryRow("SELECT COUNT(*) FROM user_node WHERE user_id = ?", claims.UID).Scan(&count)
	if count >= limit {
		respondError(w, r, http.StatusPaymentRequired, "TIER_LIMIT",
			fmt.Sprintf("Node limit reached (%d). Upgrade for more.", limit))
		return
	}

	// Create agent credential for this node
	agentName := fmt.Sprintf("node-%s-%d", body.Label, claims.UID)
	apiKey := randomHex(32)
	keyHash := hashAPIKey(apiKey)

	result, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash, trust_level, description, user_id) VALUES (?,?,?,?,?)",
		agentName, keyHash, "read", fmt.Sprintf("Node agent for %s", body.Label), claims.UID,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			respondError(w, r, http.StatusConflict, "NODE_EXISTS", "Node with this label already exists")
			return
		}
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create node credential")
		return
	}
	credID, _ := result.LastInsertId()

	// Create node record
	var wgEndpoint *string
	if body.WGEndpoint != "" {
		wgEndpoint = &body.WGEndpoint
	}
	_, err = store.Exec(
		`INSERT INTO user_node (user_id, label, wg_pubkey, wg_endpoint, wg_listen_port, interface_name, agent_credential_id)
		VALUES (?,?,?,?,?,?,?)`,
		claims.UID, body.Label, body.WGPubkey, wgEndpoint, body.ListenPort, body.Interface, credID,
	)
	if err != nil {
		// Rollback credential
		store.Exec("DELETE FROM agent_credential WHERE id = ?", credID)
		if strings.Contains(err.Error(), "UNIQUE") {
			respondError(w, r, http.StatusConflict, "NODE_EXISTS", "Node with this label already exists")
			return
		}
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create node")
		return
	}

	emitEvent("node.created", clientIP(r), claims.UID, r.UserAgent(), http.StatusCreated,
		map[string]any{"label": body.Label})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"label":   body.Label,
		"api_key": apiKey,
	})
}

// DELETE /account/nodes/{label}
func handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	label := r.PathValue("label")
	if label == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Label required")
		return
	}

	// Find the node and its credential
	var nodeID, credID int
	err := store.QueryRow(
		"SELECT id, agent_credential_id FROM user_node WHERE user_id = ? AND label = ?",
		claims.UID, label,
	).Scan(&nodeID, &credID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Node not found")
		return
	}

	// Revoke agent credential and delete node
	store.Exec("UPDATE agent_credential SET revoked_at = datetime('now') WHERE id = ?", credID)
	store.Exec("DELETE FROM user_node WHERE id = ?", nodeID)

	emitEvent("node.deleted", clientIP(r), claims.UID, r.UserAgent(), http.StatusOK,
		map[string]any{"label": label})
	jsonOK(w, map[string]any{"ok": true})
}
