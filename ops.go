package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GET /ops/sessions
func handleOpsSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	active := q.Get("active") != "false"
	limit := intOr(q.Get("limit"), 50)
	offset := intOr(q.Get("offset"), 0)
	if limit > 200 {
		limit = 200
	}

	where := "1=1"
	args := []any{}
	if active {
		where += " AND expires_at > datetime('now')"
	}
	if uid := q.Get("user_id"); uid != "" {
		where += " AND user_id = ?"
		args = append(args, uid)
	}
	args = append(args, limit, offset)

	rows, err := store.Query(
		"SELECT id, user_id, ip_address, user_agent, created_at, expires_at FROM session WHERE "+where+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	var sessions []map[string]any
	for rows.Next() {
		var id, ip, ua, created, expires string
		var uid int
		rows.Scan(&id, &uid, &ip, &ua, &created, &expires)
		sessions = append(sessions, map[string]any{
			"id": id, "user_id": uid, "ip_address": ip, "user_agent": ua,
			"created_at": created, "expires_at": expires,
		})
	}
	if sessions == nil {
		sessions = []map[string]any{}
	}
	jsonOK(w, map[string]any{"sessions": sessions, "count": len(sessions)})
}

// POST /ops/sessions/revoke
func handleOpsSessionRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope string `json:"scope"`
		ID    any    `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, 400, "INVALID_BODY", "Invalid JSON")
		return
	}

	var res int64
	switch body.Scope {
	case "all":
		r, _ := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE expires_at > datetime('now')")
		res, _ = r.RowsAffected()
	case "user":
		id, ok := numericID(body.ID)
		if !ok {
			jsonError(w, 400, "INVALID_ID", "User ID required")
			return
		}
		r, _ := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE user_id = ? AND expires_at > datetime('now')", id)
		res, _ = r.RowsAffected()
	case "session":
		sid, ok := body.ID.(string)
		if !ok || sid == "" {
			jsonError(w, 400, "INVALID_ID", "Session ID required")
			return
		}
		r, _ := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE id = ?", sid)
		res, _ = r.RowsAffected()
	default:
		jsonError(w, 400, "INVALID_SCOPE", "Scope must be all, user, or session")
		return
	}

	agent := getAgent(r)
	emitEvent("session.ops_revoke", clientIP(r), 0, r.UserAgent(), 200, map[string]any{
		"scope": body.Scope, "revoked": res, "actor": "agent:" + agent.Name,
	})
	jsonOK(w, map[string]any{"success": true, "revoked": res})
}

// POST /ops/agents
func handleOpsAgentCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		TrustLevel  string `json:"trustLevel"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonError(w, 400, "INVALID_BODY", "Invalid JSON")
		return
	}
	if body.Name == "" {
		jsonError(w, 400, "VALIDATION_ERROR", "Name required")
		return
	}
	if body.TrustLevel == "" {
		body.TrustLevel = "read"
	}
	if body.TrustLevel != "read" && body.TrustLevel != "write" {
		jsonError(w, 400, "VALIDATION_ERROR", "Trust level must be read or write")
		return
	}

	apiKey := randomHex(32) // 256-bit key
	keyHash := hashAPIKey(apiKey)

	_, err := store.Exec(
		"INSERT INTO agent_credential (name, key_hash, trust_level, description) VALUES (?,?,?,?)",
		body.Name, keyHash, body.TrustLevel, body.Description,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			jsonError(w, 409, "AGENT_EXISTS", "Agent name already exists")
			return
		}
		jsonError(w, 500, "INTERNAL_ERROR", "Failed to create agent")
		return
	}

	emitEvent("agent.provisioned", clientIP(r), 0, r.UserAgent(), 201, map[string]any{"name": body.Name})
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{
		"name": body.Name, "trustLevel": body.TrustLevel, "apiKey": apiKey,
	})
}

// DELETE /ops/agents/{name}
func handleOpsAgentRevoke(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		jsonError(w, 400, "VALIDATION_ERROR", "Agent name required")
		return
	}
	res, err := store.Exec(
		"UPDATE agent_credential SET revoked_at = datetime('now') WHERE name = ? AND revoked_at IS NULL", name,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Failed to revoke agent")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		jsonError(w, 404, "NOT_FOUND", "Agent not found")
		return
	}
	emitEvent("agent.revoked", clientIP(r), 0, r.UserAgent(), 200, map[string]any{"name": name})
	jsonOK(w, map[string]any{"success": true})
}

// GET /ops/agents
func handleOpsAgentList(w http.ResponseWriter, r *http.Request) {
	rows, err := store.Query(
		"SELECT id, name, trust_level, description, created_at, revoked_at FROM agent_credential ORDER BY created_at DESC",
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	var agents []map[string]any
	for rows.Next() {
		var id int
		var name, trust, created string
		var desc, revoked *string
		rows.Scan(&id, &name, &trust, &desc, &created, &revoked)
		a := map[string]any{
			"id": id, "name": name, "trust_level": trust, "created_at": created,
		}
		if desc != nil {
			a["description"] = *desc
		}
		if revoked != nil {
			a["revoked_at"] = *revoked
		}
		agents = append(agents, a)
	}
	if agents == nil {
		agents = []map[string]any{}
	}
	jsonOK(w, map[string]any{"agents": agents})
}

// GET /ops/events
func handleOpsEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := intOr(q.Get("limit"), 50)
	offset := intOr(q.Get("offset"), 0)
	if limit > 200 {
		limit = 200
	}

	where := "created_at >= ?"
	args := []any{parseSince(q.Get("since"))}
	if t := q.Get("type"); t != "" {
		where += " AND type = ?"
		args = append(args, t)
	}
	if uid := q.Get("user_id"); uid != "" {
		where += " AND user_id = ?"
		args = append(args, uid)
	}
	if ip := q.Get("ip"); ip != "" {
		where += " AND ip_address = ?"
		args = append(args, ip)
	}
	if actor := q.Get("actor_id"); actor != "" {
		where += " AND actor_id = ?"
		args = append(args, actor)
	}
	args = append(args, limit, offset)

	rows, err := store.Query(
		"SELECT id, type, ip_address, user_id, detail, created_at, actor_id FROM security_event WHERE "+where+" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	var events []map[string]any
	for rows.Next() {
		var id int
		var typ, ip, created, actor string
		var uid *int
		var detail *string
		rows.Scan(&id, &typ, &ip, &uid, &detail, &created, &actor)
		e := map[string]any{
			"id": id, "type": typ, "ip_address": ip, "created_at": created, "actor_id": actor,
		}
		if uid != nil {
			e["user_id"] = *uid
		}
		if detail != nil {
			e["detail"] = *detail
		}
		events = append(events, e)
	}
	if events == nil {
		events = []map[string]any{}
	}
	jsonOK(w, map[string]any{"events": events, "count": len(events)})
}

// GET /ops/events/stats
func handleOpsEventStats(w http.ResponseWriter, r *http.Request) {
	since := parseSince(r.URL.Query().Get("since"))

	rows, err := store.Query(
		"SELECT type, COUNT(*) as count FROM security_event WHERE created_at >= ? GROUP BY type", since,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	stats := map[string]int{}
	for rows.Next() {
		var typ string
		var count int
		rows.Scan(&typ, &count)
		stats[typ] = count
	}
	jsonOK(w, map[string]any{"since": since, "stats": stats})
}

// GET /ops/subscriptions/{user_id}/history
func handleOpsSubscriptionHistory(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.Atoi(r.PathValue("user_id"))
	if err != nil || uid <= 0 {
		jsonError(w, 400, "VALIDATION_ERROR", "Invalid user_id")
		return
	}

	// Current subscription state
	var tier, customerID string
	var periodEnd, createdAt, updatedAt sql.NullString
	err = store.QueryRow(
		"SELECT tier, stripe_customer_id, current_period_end, created_at, updated_at FROM user_subscription WHERE user_id = ?",
		uid,
	).Scan(&tier, &customerID, &periodEnd, &createdAt, &updatedAt)

	var current map[string]any
	if err == nil {
		current = map[string]any{
			"tier":               tier,
			"stripe_customer_id": customerID,
			"current_period_end": nullStringPtr(periodEnd),
			"created_at":         nullStringPtr(createdAt),
			"updated_at":         nullStringPtr(updatedAt),
		}
	}

	// History
	rows, err := store.Query(
		"SELECT tier_from, tier_to, reason, created_at FROM subscription_history WHERE user_id = ? ORDER BY created_at",
		uid,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	var history []map[string]any
	for rows.Next() {
		var from, to, reason, at string
		rows.Scan(&from, &to, &reason, &at)
		history = append(history, map[string]any{
			"tier_from": from, "tier_to": to, "reason": reason, "created_at": at,
		})
	}
	if history == nil {
		history = []map[string]any{}
	}

	jsonOK(w, map[string]any{
		"user_id": uid,
		"current": current,
		"history": history,
	})
}

// GET /ops/nodes
func handleOpsNodeList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	uid := q.Get("user_id")

	where := "1=1"
	args := []any{}
	if uid != "" {
		where += " AND n.user_id = ?"
		args = append(args, uid)
	}

	rows, err := store.Query(
		`SELECT n.id, n.user_id, n.label, n.wg_pubkey, n.wg_endpoint, n.allowed_ips,
			n.last_seen_at, n.created_at
		FROM user_node n WHERE `+where+` ORDER BY n.created_at DESC`,
		args...,
	)
	if err != nil {
		jsonError(w, 500, "INTERNAL_ERROR", "Query failed")
		return
	}
	defer rows.Close()

	var nodes []map[string]any
	for rows.Next() {
		var id, userID int
		var label, pubkey, allowedIPs, created string
		var endpoint, lastSeen *string
		rows.Scan(&id, &userID, &label, &pubkey, &endpoint, &allowedIPs, &lastSeen, &created)
		n := map[string]any{
			"id": id, "user_id": userID, "label": label, "wg_pubkey": pubkey,
			"allowed_ips": allowedIPs, "created_at": created,
		}
		if endpoint != nil {
			n["wg_endpoint"] = *endpoint
		}
		if lastSeen != nil {
			n["last_seen_at"] = *lastSeen
		}
		nodes = append(nodes, n)
	}
	if nodes == nil {
		nodes = []map[string]any{}
	}
	jsonOK(w, map[string]any{"nodes": nodes})
}

func nullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

// --- Helpers ---

func intOr(s string, def int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func numericID(v any) (int, bool) {
	switch id := v.(type) {
	case float64:
		return int(id), true
	case string:
		n, err := strconv.Atoi(id)
		return n, err == nil
	}
	return 0, false
}

// parseSince returns a SQL-safe datetime string for the "since" parameter.
// Defaults to 24 hours ago if empty or unparseable.
func parseSince(s string) string {
	if s == "" {
		return time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
}
