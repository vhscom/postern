package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const (
	maxPeersFree = 1
	maxPeersPro  = 10
	maxPeersTeam = 25
)

func peerLimit(tier string) int {
	switch tier {
	case "pro":
		return maxPeersPro
	case "team":
		return maxPeersTeam
	default:
		return maxPeersFree
	}
}

func getUserTier(userID int) string {
	var tier string
	err := store.QueryRow(
		"SELECT tier FROM user_subscription WHERE user_id = ? AND (current_period_end IS NULL OR current_period_end > datetime('now'))",
		userID,
	).Scan(&tier)
	if err != nil {
		return "free"
	}
	return tier
}

// GET /account/peers
func handlePeerList(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	tier := getUserTier(claims.UID)

	rows, err := store.Query(
		"SELECT label, endpoint, wg_pubkey, strftime('%Y-%m-%dT%H:%M:%SZ', created_at), strftime('%Y-%m-%dT%H:%M:%SZ', updated_at) FROM user_peer WHERE user_id = ? ORDER BY created_at",
		claims.UID,
	)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fetch peers")
		return
	}
	defer rows.Close()

	type peer struct {
		Label     string `json:"label"`
		Endpoint  string `json:"endpoint"`
		WGPubkey  string `json:"wg_pubkey"`
		CreatedAt string `json:"created_at"`
		UpdatedAt string `json:"updated_at"`
	}
	var peers []peer
	for rows.Next() {
		var p peer
		if err := rows.Scan(&p.Label, &p.Endpoint, &p.WGPubkey, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		peers = append(peers, p)
	}
	if peers == nil {
		peers = []peer{}
	}
	jsonOK(w, map[string]any{
		"peers": peers,
		"tier":  tier,
		"limit": peerLimit(tier),
	})
}

// PUT /account/peers
func handlePeerUpsert(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	var body struct {
		Label    string `json:"label"`
		Endpoint string `json:"endpoint"`
		WGPubkey string `json:"wg_pubkey"`
		Confirm  bool   `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid request body")
		return
	}

	body.Label = strings.TrimSpace(body.Label)
	if body.Label == "" {
		body.Label = "default"
	}
	body.Endpoint = strings.TrimSpace(body.Endpoint)
	body.WGPubkey = strings.TrimSpace(body.WGPubkey)

	if !validLabel(body.Label) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid label (alphanumeric, hyphens, max 32 chars)")
		return
	}
	if !validEndpoint(body.Endpoint) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid endpoint (host:port required)")
		return
	}
	if !validWGPubkey(body.WGPubkey) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid WireGuard public key")
		return
	}

	tier := getUserTier(claims.UID)
	limit := peerLimit(tier)

	var count int
	store.QueryRow("SELECT COUNT(*) FROM user_peer WHERE user_id = ?", claims.UID).Scan(&count)

	var existingEndpoint, existingWGPubkey string
	exists := store.QueryRow(
		"SELECT endpoint, wg_pubkey FROM user_peer WHERE user_id = ? AND label = ?",
		claims.UID, body.Label,
	).Scan(&existingEndpoint, &existingWGPubkey) == nil

	if exists && !body.Confirm {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]any{
			"code":    "PEER_EXISTS",
			"message": "Peer with this label already exists",
			"existing": map[string]string{
				"label":    body.Label,
				"endpoint": existingEndpoint,
				"wg_pubkey": existingWGPubkey,
			},
		})
		return
	}

	if !exists && count >= limit {
		respondError(w, r, http.StatusPaymentRequired, "TIER_LIMIT",
			fmt.Sprintf("Peer limit reached (%d). Upgrade for more.", limit))
		return
	}

	_, err := store.Exec(`
		INSERT INTO user_peer (user_id, label, endpoint, wg_pubkey)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (user_id, label) DO UPDATE SET
			endpoint = excluded.endpoint,
			wg_pubkey = excluded.wg_pubkey,
			updated_at = datetime('now')`,
		claims.UID, body.Label, body.Endpoint, body.WGPubkey,
	)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save peer")
		return
	}

	status := http.StatusOK
	if !exists {
		status = http.StatusCreated
	}
	emitEvent("peer.upsert", clientIP(r), claims.UID, r.UserAgent(), status,
		map[string]any{"label": body.Label})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"ok": true, "label": body.Label})
}

// DELETE /account/peers/{label}
func handlePeerDelete(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	label := r.PathValue("label")
	if label == "" {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Label required")
		return
	}

	result, err := store.Exec("DELETE FROM user_peer WHERE user_id = ? AND label = ?", claims.UID, label)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete peer")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Peer not found")
		return
	}

	emitEvent("peer.delete", clientIP(r), claims.UID, r.UserAgent(), http.StatusOK,
		map[string]any{"label": label})
	jsonOK(w, map[string]any{"ok": true})
}

// --- Validation ---

func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func validEndpoint(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	i := strings.LastIndex(s, ":")
	return i > 0 && i < len(s)-1
}

func validWGPubkey(s string) bool {
	// WireGuard public keys: 32 bytes base64-encoded = 44 chars ending with =
	if len(s) != 44 || s[43] != '=' {
		return false
	}
	for _, c := range s[:43] {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
			return false
		}
	}
	return true
}
