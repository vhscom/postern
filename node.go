package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GET /account/nodes
func handleNodeList(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tier := getUserTier(claims.UID)

	rows, err := store.Query(
		`SELECT label, wg_pubkey, wg_endpoint, wg_listen_port, allowed_ips, persistent_keepalive,
			interface_name, wg_endpoint_source, last_seen_at, created_at, updated_at
		FROM user_node WHERE user_id = ? ORDER BY created_at`,
		claims.UID,
	)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch nodes")
		return
	}
	defer rows.Close()

	type node struct {
		Label          string  `json:"label"`
		WGPubkey       string  `json:"wg_pubkey"`
		WGEndpoint     *string `json:"wg_endpoint"`
		ListenPort     int     `json:"wg_listen_port"`
		AllowedIPs     string  `json:"allowed_ips"`
		Keepalive      int     `json:"persistent_keepalive"`
		Interface      string  `json:"interface_name"`
		EndpointSource string  `json:"wg_endpoint_source"`
		Status         string  `json:"status"`
		LastSeenAt     *string `json:"last_seen_at"`
		CreatedAt      string  `json:"created_at"`
		UpdatedAt      string  `json:"updated_at"`
	}
	nodes := make([]node, 0)
	for rows.Next() {
		var n node
		if err := rows.Scan(&n.Label, &n.WGPubkey, &n.WGEndpoint, &n.ListenPort, &n.AllowedIPs,
			&n.Keepalive, &n.Interface, &n.EndpointSource, &n.LastSeenAt, &n.CreatedAt, &n.UpdatedAt); err != nil {
			continue
		}
		n.Status = computeNodeStatus(n.LastSeenAt)
		nodes = append(nodes, n)
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
		AllowedIPs string `json:"allowed_ips"`
		Keepalive  int    `json:"persistent_keepalive"`
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
	body.AllowedIPs = strings.TrimSpace(body.AllowedIPs)
	if body.AllowedIPs == "" {
		ip, err := allocateMeshIP(claims.UID)
		if err != nil {
			respondError(w, r, http.StatusConflict, "IP_EXHAUSTED", err.Error())
			return
		}
		body.AllowedIPs = ip
	} else if !validAllowedIPs(body.AllowedIPs) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid allowed_ips (must be CIDR, e.g. 10.0.0.1/32)")
		return
	}
	if body.ListenPort == 0 {
		body.ListenPort = 51820
	}
	if body.Keepalive == 0 {
		body.Keepalive = 25
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

	// Determine endpoint source
	var wgEndpoint *string
	endpointSource := "stun"
	if body.WGEndpoint != "" {
		wgEndpoint = &body.WGEndpoint
		endpointSource = "manual"
	}

	apiKey, _, err := insertNodeWithCredential(nodeCreateOpts{
		UserID:         claims.UID,
		Label:          body.Label,
		WGPubkey:       body.WGPubkey,
		WGEndpoint:     wgEndpoint,
		ListenPort:     body.ListenPort,
		AllowedIPs:     body.AllowedIPs,
		Keepalive:      body.Keepalive,
		Interface:      body.Interface,
		EndpointSource: endpointSource,
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			respondError(w, r, http.StatusConflict, "NODE_EXISTS", "Node with this label already exists")
			return
		}
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create node")
		return
	}

	emitEvent("node.created", clientIP(r), claims.UID, r.UserAgent(), http.StatusCreated,
		map[string]any{"label": body.Label})

	go notifyNodeSync(claims.UID)

	resp := map[string]any{
		"label":   body.Label,
		"api_key": apiKey,
		"mesh_ip": body.AllowedIPs,
	}
	if u := buildOpsURL(r); u != "" {
		resp["ops_url"] = u
	}

	jsonCreated(w, resp)
}

// PUT /account/nodes/{label}
func handleNodeUpdate(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	label := r.PathValue("label")
	if label == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Label required")
		return
	}

	var nodeID int
	err := store.QueryRow(
		"SELECT id FROM user_node WHERE user_id = ? AND label = ?",
		claims.UID, label,
	).Scan(&nodeID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Node not found")
		return
	}

	var body struct {
		WGEndpoint *string `json:"wg_endpoint"`
		ListenPort *int    `json:"wg_listen_port"`
		AllowedIPs *string `json:"allowed_ips"`
		Keepalive  *int    `json:"persistent_keepalive"`
		Interface  *string `json:"interface_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	// Build dynamic update
	sets := []string{"updated_at = datetime('now')"}
	args := []any{}

	if body.WGEndpoint != nil {
		sets = append(sets, "wg_endpoint = ?", "wg_endpoint_source = ?")
		v := strings.TrimSpace(*body.WGEndpoint)
		if v == "" {
			args = append(args, nil, "manual")
		} else {
			args = append(args, v, "manual")
		}
	}
	if body.ListenPort != nil {
		sets = append(sets, "wg_listen_port = ?")
		args = append(args, *body.ListenPort)
	}
	if body.AllowedIPs != nil {
		v := strings.TrimSpace(*body.AllowedIPs)
		if v == "" {
			respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "allowed_ips cannot be empty")
			return
		}
		if !validAllowedIPs(v) {
			respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid allowed_ips (must be CIDR, e.g. 10.0.0.1/32)")
			return
		}
		sets = append(sets, "allowed_ips = ?")
		args = append(args, v)
	}
	if body.Keepalive != nil {
		sets = append(sets, "persistent_keepalive = ?")
		args = append(args, *body.Keepalive)
	}
	if body.Interface != nil {
		sets = append(sets, "interface_name = ?")
		args = append(args, strings.TrimSpace(*body.Interface))
	}

	if len(args) == 0 {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "No fields to update")
		return
	}

	args = append(args, nodeID)
	query := fmt.Sprintf("UPDATE user_node SET %s WHERE id = ?", strings.Join(sets, ", "))
	if _, err := store.Exec(query, args...); err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update node")
		return
	}

	emitEvent("node.updated", clientIP(r), claims.UID, r.UserAgent(), http.StatusOK,
		map[string]any{"label": label})

	go notifyNodeSync(claims.UID)

	jsonOK(w, map[string]any{"ok": true, "label": label})
}

// DELETE /account/nodes/{label}
func handleNodeDelete(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	label := r.PathValue("label")
	if label == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Label required")
		return
	}

	var nodeID, credID int
	err := store.QueryRow(
		"SELECT id, agent_credential_id FROM user_node WHERE user_id = ? AND label = ?",
		claims.UID, label,
	).Scan(&nodeID, &credID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Node not found")
		return
	}

	store.Exec("UPDATE invite_token SET used_by_node_id = NULL WHERE used_by_node_id = ?", nodeID)
	if _, err = store.Exec("DELETE FROM user_node WHERE id = ?", nodeID); err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete node")
		return
	}
	store.Exec("DELETE FROM agent_credential WHERE id = ?", credID)

	emitEvent("node.deleted", clientIP(r), claims.UID, r.UserAgent(), http.StatusOK,
		map[string]any{"label": label})

	// Node left the mesh — notify remaining connected nodes
	go notifyNodeSync(claims.UID)

	jsonOK(w, map[string]any{"ok": true})
}

// buildOpsURL constructs the ops surface URL from the current request, or "" if not configured.
func buildOpsURL(r *http.Request) string {
	if cfg.OpsAddr == "" {
		return ""
	}
	host := r.Host
	if i := strings.LastIndex(host, ":"); i != -1 {
		host = host[:i]
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	port := strings.TrimPrefix(cfg.OpsAddr, ":")
	return fmt.Sprintf("%s://%s:%s", scheme, host, port)
}

// nodeCreateOpts holds the parameters for creating a node with its agent credential.
type nodeCreateOpts struct {
	UserID         int
	Label          string
	WGPubkey       string
	WGEndpoint     *string
	ListenPort     int
	AllowedIPs     string
	Keepalive      int
	Interface      string
	EndpointSource string
}

// insertNodeWithCredential creates an agent credential and node record.
// Returns the API key for the agent and the node ID, or an error.
func insertNodeWithCredential(opts nodeCreateOpts) (apiKey string, nodeID int64, err error) {
	agentName := fmt.Sprintf("node-%s-%d", opts.Label, opts.UserID)
	apiKey = randomHex(32)
	keyHash := hashAPIKey(apiKey)

	result, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash, trust_level, description, user_id) VALUES (?,?,?,?,?)",
		agentName, keyHash, "read", fmt.Sprintf("Node agent for %s", opts.Label), opts.UserID,
	)
	if err != nil {
		return "", 0, fmt.Errorf("credential: %w", err)
	}
	credID, _ := result.LastInsertId()

	nodeResult, err := store.Exec(
		`INSERT INTO user_node (user_id, label, wg_pubkey, wg_endpoint, wg_listen_port, allowed_ips, persistent_keepalive, interface_name, agent_credential_id, wg_endpoint_source)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		opts.UserID, opts.Label, opts.WGPubkey, opts.WGEndpoint, opts.ListenPort, opts.AllowedIPs, opts.Keepalive, opts.Interface, credID, opts.EndpointSource,
	)
	if err != nil {
		store.Exec("DELETE FROM agent_credential WHERE id = ?", credID)
		return "", 0, fmt.Errorf("node: %w", err)
	}

	nodeID, _ = nodeResult.LastInsertId()
	return apiKey, nodeID, nil
}

// allocateMeshIP assigns the next available IP from 10.0.0.0/24 for a user's mesh.
func allocateMeshIP(userID int) (string, error) {
	rows, err := store.Query("SELECT allowed_ips FROM user_node WHERE user_id = ?", userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	used := map[string]bool{}
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		used[ip] = true
	}

	for i := 1; i <= 254; i++ {
		candidate := fmt.Sprintf("10.0.0.%d/32", i)
		if !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no available mesh IPs (254 limit)")
}

// computeNodeStatus returns "online", "idle", or "offline" based on last_seen_at.
func computeNodeStatus(lastSeenAt *string) string {
	if lastSeenAt == nil {
		return "offline"
	}
	t, err := time.Parse("2006-01-02 15:04:05", *lastSeenAt)
	if err != nil {
		return "offline"
	}
	age := time.Since(t)
	switch {
	case age < 2*time.Minute:
		return "online"
	case age < 10*time.Minute:
		return "idle"
	default:
		return "offline"
	}
}
