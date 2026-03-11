package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Agent WebSocket close codes
const (
	wsNormal            = 1000
	wsHandshakeTimeout  = 4001
	wsProtocolError     = 4002
	wsRateLimited       = 4008
	wsCredentialRevoked = 4010
	wsPingTimeout       = 4011
)

// Agent WebSocket limits
const (
	wsHandshakeDeadline = 5 * time.Second
	wsHeartbeatInterval = 25 * time.Second
	wsPingDeadline      = 90 * time.Second
	wsMsgRateWindow     = 60 * time.Second
	wsMsgRateMax        = 60
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true // non-browser clients
		}
		if cfg.WSAllowedOrigins == "" {
			return false // block all browser origins by default
		}
		for _, allowed := range strings.Split(cfg.WSAllowedOrigins, ",") {
			if strings.TrimSpace(allowed) == origin {
				return true
			}
		}
		return false
	},
}

// Allowed capabilities by trust level
var capsByTrust = map[string]map[string]bool{
	"read":  {"query_events": true, "query_sessions": true, "subscribe_events": true},
	"write": {"query_events": true, "query_sessions": true, "subscribe_events": true, "revoke_session": true},
}

func handleOpsWS(w http.ResponseWriter, r *http.Request) {
	agent := getAgent(r)
	if agent == nil {
		emitEvent("ws.unauthorized", clientIP(r), 0, r.UserAgent(), 401, nil)
		jsonError(w, 401, "UNAUTHORIZED", "Agent key required")
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.SetReadLimit(1 << 20) // 1MB
	connID := randomHex(8)

	emitEvent("ws.connect", clientIP(r), 0, r.UserAgent(), 101, map[string]any{
		"connectionId": connID, "agent": agent.Name,
	})

	// Wait for capability negotiation
	granted := negotiateCapabilities(conn, agent, connID)
	if granted == nil {
		return
	}

	// Start heartbeat
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	go heartbeatLoop(conn, agent, connID, done, closeDone)

	// Subscription management
	subs := &subscriptions{
		active: make(map[string]chan struct{}),
	}

	// Message rate limiting
	var msgCount int
	windowStart := time.Now()

	// Message loop
	for {
		conn.SetReadDeadline(time.Now().Add(wsPingDeadline))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Rate limit
		now := time.Now()
		if now.Sub(windowStart) > wsMsgRateWindow {
			windowStart = now
			msgCount = 0
		}
		msgCount++
		if msgCount > wsMsgRateMax {
			closeWSAgent(conn, wsRateLimited, "Rate limited")
			break
		}

		handleAgentMessage(conn, agent, granted, raw, connID, subs)
	}

	subs.stopAll()
	closeDone()
	emitEvent("ws.disconnect", clientIP(r), 0, r.UserAgent(), 200, map[string]any{
		"connectionId": connID, "agent": agent.Name,
	})
}

func negotiateCapabilities(conn *websocket.Conn, agent *AgentPrincipal, connID string) map[string]bool {
	conn.SetReadDeadline(time.Now().Add(wsHandshakeDeadline))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		closeWSAgent(conn, wsHandshakeTimeout, "Handshake timeout")
		return nil
	}

	var msg struct {
		Type         string   `json:"type"`
		Capabilities []string `json:"capabilities"`
	}
	if json.Unmarshal(raw, &msg) != nil || msg.Type != "capability.request" {
		closeWSAgent(conn, wsProtocolError, "Expected capability.request")
		return nil
	}

	allowed := capsByTrust[agent.TrustLevel]
	granted := map[string]bool{}
	var denied []map[string]string
	for _, cap := range msg.Capabilities {
		if allowed[cap] {
			granted[cap] = true
		} else {
			denied = append(denied, map[string]string{"capability": cap, "reason": "not_allowed"})
		}
	}

	grantedList := make([]string, 0, len(granted))
	for c := range granted {
		grantedList = append(grantedList, c)
	}

	resp := map[string]any{
		"type":          "capability.granted",
		"connection_id": connID,
		"agent":         agent.Name,
		"granted":       grantedList,
		"denied":        denied,
	}
	b, _ := json.Marshal(resp)
	conn.WriteMessage(websocket.TextMessage, b)

	emitEvent("ws.capability_granted", "", 0, "", 200, map[string]any{
		"connectionId": connID, "agent": agent.Name,
		"granted": grantedList, "denied": denied,
	})
	return granted
}

func heartbeatLoop(conn *websocket.Conn, agent *AgentPrincipal, connID string, done chan struct{}, closeDone func()) {
	ticker := time.NewTicker(wsHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Verify agent credential still valid
			var revokedAt *string
			err := store.QueryRow(
				"SELECT revoked_at FROM agent_credential WHERE id = ?", agent.ID,
			).Scan(&revokedAt)
			if err != nil || revokedAt != nil {
				emitEvent("ws.credential_revoked", "", 0, "", 200, map[string]any{
					"connectionId": connID, "agent": agent.Name,
				})
				closeWSAgent(conn, wsCredentialRevoked, "Credential revoked")
				closeDone()
				return
			}

			hb := map[string]any{
				"type":             "heartbeat",
				"ts":               time.Now().Unix(),
				"next_check_ms":    wsHeartbeatInterval.Milliseconds(),
				"ping_timeout_ms":  wsPingDeadline.Milliseconds(),
			}
			b, _ := json.Marshal(hb)
			conn.WriteMessage(websocket.TextMessage, b)
		}
	}
}

func handleAgentMessage(conn *websocket.Conn, agent *AgentPrincipal, granted map[string]bool, raw []byte, connID string, subs *subscriptions) {
	var msg struct {
		Type    string          `json:"type"`
		ID      string          `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(raw, &msg) != nil {
		sendWSError(conn, "", "PARSE_ERROR", "Invalid JSON")
		return
	}

	switch msg.Type {
	case "ping":
		resp := map[string]any{"type": "pong"}
		if msg.ID != "" {
			resp["id"] = msg.ID
		}
		b, _ := json.Marshal(resp)
		conn.WriteMessage(websocket.TextMessage, b)

	case "query_events":
		if !granted["query_events"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSQueryEvents(conn, msg.ID, msg.Payload)

	case "query_sessions":
		if !granted["query_sessions"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSQuerySessions(conn, msg.ID, msg.Payload)

	case "revoke_session":
		if !granted["revoke_session"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSRevokeSession(conn, msg.ID, msg.Payload, agent, connID)

	case "subscribe_events":
		if !granted["subscribe_events"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWSSubscribeEvents(conn, msg.ID, msg.Payload, subs)

	case "unsubscribe_events":
		handleWSUnsubscribeEvents(conn, msg.ID, subs)

	default:
		sendWSError(conn, msg.ID, "UNKNOWN_TYPE", "Unknown message type: "+msg.Type)
	}
}

func handleWSQueryEvents(conn *websocket.Conn, id string, payload json.RawMessage) {
	var p struct {
		Since     string `json:"since"`
		EventType string `json:"event_type"`
		UserID    *int   `json:"user_id"`
		IP        string `json:"ip"`
		Limit     int    `json:"limit"`
		Aggregate bool   `json:"aggregate"`
	}
	json.Unmarshal(payload, &p)
	if p.Limit <= 0 || p.Limit > 200 {
		p.Limit = 50
	}

	since := parseSince(p.Since)

	if p.Aggregate {
		rows, err := store.Query(
			"SELECT type, COUNT(*) FROM security_event WHERE created_at >= ? GROUP BY type", since,
		)
		if err != nil {
			sendWSError(conn, id, "QUERY_ERROR", err.Error())
			return
		}
		defer rows.Close()
		stats := map[string]int{}
		for rows.Next() {
			var t string
			var c int
			rows.Scan(&t, &c)
			stats[t] = c
		}
		sendWSResult(conn, id, "query_events", map[string]any{"stats": stats})
		return
	}

	where := "created_at >= ?"
	args := []any{since}
	if p.EventType != "" {
		where += " AND type = ?"
		args = append(args, p.EventType)
	}
	if p.UserID != nil {
		where += " AND user_id = ?"
		args = append(args, *p.UserID)
	}
	if p.IP != "" {
		where += " AND ip_address = ?"
		args = append(args, p.IP)
	}
	args = append(args, p.Limit)

	rows, err := store.Query(
		"SELECT id, type, ip_address, user_id, detail, created_at, actor_id FROM security_event WHERE "+where+" ORDER BY created_at DESC LIMIT ?",
		args...,
	)
	if err != nil {
		sendWSError(conn, id, "QUERY_ERROR", err.Error())
		return
	}
	defer rows.Close()

	var events []map[string]any
	for rows.Next() {
		var eid int
		var typ, ip, created, actor string
		var uid *int
		var detail *string
		rows.Scan(&eid, &typ, &ip, &uid, &detail, &created, &actor)
		e := map[string]any{"id": eid, "type": typ, "ip_address": ip, "created_at": created, "actor_id": actor}
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
	sendWSResult(conn, id, "query_events", map[string]any{"events": events})
}

func handleWSQuerySessions(conn *websocket.Conn, id string, payload json.RawMessage) {
	var p struct {
		UserID *int `json:"user_id"`
		Active bool `json:"active"`
		Limit  int  `json:"limit"`
	}
	p.Active = true
	p.Limit = 50
	json.Unmarshal(payload, &p)
	if p.Limit > 200 {
		p.Limit = 200
	}

	where := "1=1"
	args := []any{}
	if p.Active {
		where += " AND expires_at > datetime('now')"
	}
	if p.UserID != nil {
		where += " AND user_id = ?"
		args = append(args, *p.UserID)
	}
	args = append(args, p.Limit)

	rows, err := store.Query(
		"SELECT id, user_id, ip_address, user_agent, created_at, expires_at FROM session WHERE "+where+" ORDER BY created_at DESC LIMIT ?",
		args...,
	)
	if err != nil {
		sendWSError(conn, id, "QUERY_ERROR", err.Error())
		return
	}
	defer rows.Close()

	var sessions []map[string]any
	for rows.Next() {
		var sid, ip, ua, created, expires string
		var uid int
		rows.Scan(&sid, &uid, &ip, &ua, &created, &expires)
		sessions = append(sessions, map[string]any{
			"id": sid, "user_id": uid, "ip_address": ip, "user_agent": ua,
			"created_at": created, "expires_at": expires,
		})
	}
	if sessions == nil {
		sessions = []map[string]any{}
	}
	sendWSResult(conn, id, "query_sessions", map[string]any{"sessions": sessions})
}

func handleWSRevokeSession(conn *websocket.Conn, id string, payload json.RawMessage, agent *AgentPrincipal, connID string) {
	var p struct {
		Scope    string `json:"scope"`
		TargetID any    `json:"target_id"`
	}
	json.Unmarshal(payload, &p)

	var res int64
	switch p.Scope {
	case "all":
		r, _ := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE expires_at > datetime('now')")
		res, _ = r.RowsAffected()
	case "user":
		uid, ok := numericID(p.TargetID)
		if !ok {
			sendWSError(conn, id, "INVALID_ID", "User ID required")
			return
		}
		r, _ := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE user_id = ? AND expires_at > datetime('now')", uid)
		res, _ = r.RowsAffected()
	case "session":
		sid, ok := p.TargetID.(string)
		if !ok || sid == "" {
			sendWSError(conn, id, "INVALID_ID", "Session ID required")
			return
		}
		r, _ := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE id = ?", sid)
		res, _ = r.RowsAffected()
	default:
		sendWSError(conn, id, "INVALID_SCOPE", "Scope must be all, user, or session")
		return
	}

	emitEvent("session.ops_revoke", "", 0, "", 200, map[string]any{
		"scope": p.Scope, "revoked": res, "actor": "agent:" + agent.Name, "connectionId": connID,
	})
	sendWSResult(conn, id, "revoke_session", map[string]any{"success": true, "revoked": res})
}

// --- WS helpers ---

func sendWSResult(conn *websocket.Conn, id, typ string, payload any) {
	msg := map[string]any{"type": typ + ".result", "payload": payload}
	if id != "" {
		msg["id"] = id
	}
	b, _ := json.Marshal(msg)
	conn.WriteMessage(websocket.TextMessage, b)
}

func sendWSError(conn *websocket.Conn, id, code, message string) {
	msg := map[string]any{"type": "error", "code": code, "message": message}
	if id != "" {
		msg["id"] = id
	}
	b, _ := json.Marshal(msg)
	conn.WriteMessage(websocket.TextMessage, b)
}

func closeWSAgent(conn *websocket.Conn, code int, reason string) {
	msg := websocket.FormatCloseMessage(code, reason)
	conn.WriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
	conn.Close()
}

// --- Event subscription polling ---

const (
	subFallbackInterval = 30 * time.Second // safety net if broadcast is missed
	subBackpressureAt   = 100
)

type subscriptions struct {
	mu     sync.Mutex
	active map[string]chan struct{} // key → stop channel
}

func (s *subscriptions) start(key string, stop chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.active[key]; ok {
		close(old) // stop previous
	}
	s.active[key] = stop
}

func (s *subscriptions) stop(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.active[key]; ok {
		close(ch)
		delete(s.active, key)
		return true
	}
	return false
}

func (s *subscriptions) stopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, ch := range s.active {
		close(ch)
		delete(s.active, k)
	}
}

func handleWSSubscribeEvents(conn *websocket.Conn, id string, payload json.RawMessage, subs *subscriptions) {
	var p struct {
		Types []string `json:"types"`
	}
	json.Unmarshal(payload, &p)

	// Acknowledge subscription
	ack := map[string]any{
		"type": "subscribe_events.result",
		"ok":   true,
		"payload": map[string]any{
			"mode": "realtime",
		},
	}
	if id != "" {
		ack["id"] = id
	}
	b, _ := json.Marshal(ack)
	conn.WriteMessage(websocket.TextMessage, b)

	stop := make(chan struct{})
	subs.start("events", stop)

	// Start subscription goroutine — wakes on broadcast or fallback ticker
	go func() {
		highWaterMark := time.Now().UTC().Format("2006-01-02 15:04:05")
		ticker := time.NewTicker(subFallbackInterval)
		defer ticker.Stop()

		for {
			sig := eventSignal()
			select {
			case <-stop:
				return
			case <-sig:
				// new event broadcast — immediate wake
			case <-ticker.C:
				// fallback poll
			}

			events := pollNewEvents(highWaterMark, p.Types)
			if len(events) == 0 {
				continue
			}

			if last, ok := events[len(events)-1]["created_at"].(string); ok {
				highWaterMark = last
			}

			for _, e := range events {
				msg := map[string]any{
					"type":    "event",
					"payload": e,
				}
				b, _ := json.Marshal(msg)
				if err := conn.WriteMessage(websocket.TextMessage, b); err != nil {
					return
				}
			}

			if len(events) >= subBackpressureAt {
				bp := map[string]any{
					"type":    "subscription.backpressure",
					"payload": map[string]any{"queued": len(events)},
				}
				b, _ := json.Marshal(bp)
				conn.WriteMessage(websocket.TextMessage, b)
			}
		}
	}()
}

func handleWSUnsubscribeEvents(conn *websocket.Conn, id string, subs *subscriptions) {
	stopped := subs.stop("events")
	sendWSResult(conn, id, "unsubscribe_events", map[string]any{"unsubscribed": stopped})
}

func pollNewEvents(since string, types []string) []map[string]any {
	where := "created_at > ?"
	args := []any{since}

	if len(types) > 0 {
		clauses := make([]string, 0, len(types))
		for _, t := range types {
			if strings.Contains(t, "*") {
				// Wildcard: login.* → login.%
				clauses = append(clauses, "type LIKE ?")
				args = append(args, strings.ReplaceAll(t, "*", "%"))
			} else {
				clauses = append(clauses, "type = ?")
				args = append(args, t)
			}
		}
		where += " AND (" + strings.Join(clauses, " OR ") + ")"
	}

	rows, err := store.Query(
		"SELECT id, type, ip_address, user_id, user_agent, status, detail, created_at, actor_id FROM security_event WHERE "+where+" ORDER BY created_at ASC LIMIT 200",
		args...,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var events []map[string]any
	for rows.Next() {
		var eid, status int
		var typ, ip, created, actor string
		var uid *int
		var ua, detail *string
		rows.Scan(&eid, &typ, &ip, &uid, &ua, &status, &detail, &created, &actor)
		e := map[string]any{
			"event_id": eid, "event_type": typ, "ip_address": ip,
			"status": status, "created_at": created, "actor_id": actor,
		}
		if uid != nil {
			e["user_id"] = *uid
		}
		if ua != nil {
			e["user_agent"] = *ua
		}
		if detail != nil {
			var parsed any
			if json.Unmarshal([]byte(*detail), &parsed) == nil {
				e["detail"] = parsed
			} else {
				e["detail"] = *detail
			}
		}
		events = append(events, e)
	}
	return events
}

