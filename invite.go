package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// POST /account/nodes/invite — create a join token for adding nodes without login
func handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)

	token := randomHex(24)
	tokenHash := hashAPIKey(token)

	_, err := store.Exec(
		"INSERT INTO invite_token (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
		tokenHash, claims.UID, time.Now().Add(24*time.Hour).UTC().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create invite")
		return
	}

	emitEvent("invite.created", clientIP(r), claims.UID, r.UserAgent(), http.StatusCreated, nil)

	jsonCreated(w, map[string]any{
		"token":        token,
		"expires_in":   "24h",
		"join_command": fmt.Sprintf("postern join %s %s", cfg.BaseURL, token),
	})
}

// POST /join — redeem a join token to add a node (no auth required)
func handleJoinRedeem(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token    string `json:"token"`
		Label    string `json:"label"`
		WGPubkey string `json:"wg_pubkey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	body.Token = strings.TrimSpace(body.Token)
	if body.Token == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Token required")
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

	tokenHash := hashAPIKey(body.Token)

	tx, err := store.Begin()
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to redeem token")
		return
	}
	defer tx.Rollback()

	// Look up and validate token
	var tokenID, userID int
	var expiresAt string
	var usedAt *string
	err = tx.QueryRow(
		"SELECT id, user_id, expires_at, used_at FROM invite_token WHERE token_hash = ?",
		tokenHash,
	).Scan(&tokenID, &userID, &expiresAt, &usedAt)
	if err != nil {
		respondError(w, r, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token")
		return
	}
	if usedAt != nil {
		respondError(w, r, http.StatusConflict, "TOKEN_USED", "Token already used")
		return
	}
	expiry, _ := time.Parse("2006-01-02 15:04:05", expiresAt)
	if time.Now().After(expiry) {
		respondError(w, r, http.StatusUnauthorized, "TOKEN_EXPIRED", "Token expired")
		return
	}

	// Check tier limit
	tier := getUserTier(tx, userID)
	limit := nodeLimit(tier)
	var count int
	tx.QueryRow("SELECT COUNT(*) FROM user_node WHERE user_id = ?", userID).Scan(&count)
	if count >= limit {
		respondError(w, r, http.StatusPaymentRequired, "TIER_LIMIT",
			fmt.Sprintf("Node limit reached (%d). Upgrade for more.", limit))
		return
	}

	// Auto-assign mesh IP
	meshIP, err := allocateMeshIP(tx, userID)
	if err != nil {
		respondError(w, r, http.StatusConflict, "IP_EXHAUSTED", err.Error())
		return
	}

	apiKey, nodeID, err := insertNodeWithCredential(tx, nodeCreateOpts{
		UserID:         userID,
		Label:          body.Label,
		WGPubkey:       body.WGPubkey,
		ListenPort:     51820,
		AllowedIPs:     meshIP,
		Keepalive:      25,
		Interface:      "wg0",
		EndpointSource: "stun",
	})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			respondError(w, r, http.StatusConflict, "NODE_EXISTS", "Node with this label already exists")
			return
		}
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create node")
		return
	}

	tx.Exec("UPDATE invite_token SET used_at = datetime('now'), used_by_node_id = ? WHERE id = ?", nodeID, tokenID)

	if err := tx.Commit(); err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to redeem token")
		return
	}

	emitEvent("node.joined", clientIP(r), userID, r.UserAgent(), http.StatusCreated,
		map[string]any{"label": body.Label, "node_id": nodeID})

	go notifyNodeSync(userID)

	resp := map[string]any{
		"api_key": apiKey,
		"mesh_ip": meshIP,
		"label":   body.Label,
	}
	if u := buildOpsURL(r); u != "" {
		resp["ops_url"] = u
	}

	jsonCreated(w, resp)
}
