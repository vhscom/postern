package main

import (
	"encoding/json"
	"log"
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

// checkWSOrigin validates the Origin header against the configured allowlist.
// Non-browser clients (no Origin) are always allowed.
func checkWSOrigin(r *http.Request) bool {
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
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: checkWSOrigin,
}

// wsConn wraps a websocket.Conn with a mutex for safe concurrent writes.
type wsConn struct {
	*websocket.Conn
	wmu sync.Mutex
}

func (c *wsConn) safeWrite(messageType int, data []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.Conn.WriteMessage(messageType, data)
}

func (c *wsConn) safeWriteControl(messageType int, data []byte, deadline time.Time) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.Conn.WriteControl(messageType, data, deadline)
}

// Allowed capabilities by trust level.
// Node-bound agents (user_id set) have ops caps stripped during negotiation
// and are blocked from ops REST endpoints by requireOpsAgent.
var capsByTrust = map[string]map[string]bool{
	"read":  {"query_events": true, "query_sessions": true, "subscribe_events": true, "wg_sync": true, "wg_status": true, "endpoint_discovery": true, "key_rotate": true},
	"write": {"query_events": true, "query_sessions": true, "subscribe_events": true, "revoke_session": true, "wg_sync": true, "wg_status": true, "endpoint_discovery": true, "key_rotate": true},
}

func handleOpsWS(w http.ResponseWriter, r *http.Request) {
	agent := getAgent(r)
	if agent == nil {
		emitEvent("ws.unauthorized", clientIP(r), 0, r.UserAgent(), 401, nil)
		jsonError(w, 401, "UNAUTHORIZED", "Agent key required")
		return
	}

	raw, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn := &wsConn{Conn: raw}
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

	// Register as node agent if applicable
	var nodeID, userID int
	if granted["wg_sync"] || granted["wg_status"] {
		nodeID, userID = lookupNodeForAgent(agent.ID)
		if nodeID > 0 {
			registerNode(&connectedNode{
				conn: conn, agentID: agent.ID, userID: userID, nodeID: nodeID,
			})
			defer func() {
				unregisterNode(nodeID)
				cleanupRelayBindings(nodeID)
			}()

			// Send full sync on connect
			go notifyNodeSync(userID)
		}
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
		messageType, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Binary frames: relay packets (separate rate limit in relay.go)
		if messageType == websocket.BinaryMessage {
			if nodeID > 0 {
				handleRelayPacket(nodeID, raw)
			}
			continue
		}

		// Rate limit text messages
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

		handleAgentMessage(conn, agent, granted, raw, connID, subs, nodeID, userID)
	}

	subs.stopAll()
	closeDone()
	emitEvent("ws.disconnect", clientIP(r), 0, r.UserAgent(), 200, map[string]any{
		"connectionId": connID, "agent": agent.Name,
	})
}

func negotiateCapabilities(conn *wsConn, agent *AgentPrincipal, connID string) map[string]bool {
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
	denied := []map[string]string{}

	// Ops capabilities are only available to ops agents (no user_id).
	// Node-bound agents are restricted to mesh capabilities.
	opsCaps := map[string]bool{"query_events": true, "query_sessions": true, "subscribe_events": true, "revoke_session": true}

	for _, cap := range msg.Capabilities {
		if !allowed[cap] {
			denied = append(denied, map[string]string{"capability": cap, "reason": "not_allowed"})
		} else if agent.UserID != nil && opsCaps[cap] {
			denied = append(denied, map[string]string{"capability": cap, "reason": "not_allowed"})
		} else {
			granted[cap] = true
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
	conn.safeWrite(websocket.TextMessage, b)

	emitEvent("ws.capability_granted", "", 0, "", 200, map[string]any{
		"connectionId": connID, "agent": agent.Name,
		"granted": grantedList, "denied": denied,
	})
	return granted
}

func heartbeatLoop(conn *wsConn, agent *AgentPrincipal, connID string, done chan struct{}, closeDone func()) {
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
				"type":            "heartbeat",
				"ts":              time.Now().Unix(),
				"next_check_ms":   wsHeartbeatInterval.Milliseconds(),
				"ping_timeout_ms": wsPingDeadline.Milliseconds(),
			}
			b, _ := json.Marshal(hb)
			conn.safeWrite(websocket.TextMessage, b)
		}
	}
}

func handleAgentMessage(conn *wsConn, agent *AgentPrincipal, granted map[string]bool, raw []byte, connID string, subs *subscriptions, nodeID, userID int) {
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
		conn.safeWrite(websocket.TextMessage, b)

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

	case "wg.status":
		if !granted["wg_status"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleWGStatus(agent, msg.Payload)

	case "wg.sync.result":
		// Acknowledgement from node agent — log only
		var p struct {
			Success bool   `json:"success"`
			Error   string `json:"error"`
		}
		json.Unmarshal(msg.Payload, &p)
		if !p.Success {
			log.Printf("wg.sync.result: agent=%s error=%s", agent.Name, p.Error)
		}

	case "endpoint.discovered":
		if !granted["endpoint_discovery"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleEndpointDiscovered(conn, agent, msg.ID, msg.Payload)

	case "key.rotate":
		if !granted["key_rotate"] {
			sendWSError(conn, msg.ID, "NOT_GRANTED", "Capability not granted")
			return
		}
		handleKeyRotate(conn, agent, msg.ID, msg.Payload)

	case "relay.bind":
		if nodeID == 0 {
			sendWSError(conn, msg.ID, "NOT_NODE", "Not registered as a node")
			return
		}
		handleRelayBind(conn, msg.ID, nodeID, userID, msg.Payload)

	case "relay.unbind":
		if nodeID == 0 {
			return
		}
		handleRelayUnbind(nodeID, msg.Payload)

	default:
		sendWSError(conn, msg.ID, "UNKNOWN_TYPE", "Unknown message type: "+msg.Type)
	}
}

// handleEndpointDiscovered processes a STUN-discovered endpoint from an agent.
func handleEndpointDiscovered(conn *wsConn, agent *AgentPrincipal, id string, payload json.RawMessage) {
	var p struct {
		Endpoint string `json:"endpoint"`
	}
	if json.Unmarshal(payload, &p) != nil || p.Endpoint == "" {
		sendWSError(conn, id, "VALIDATION_ERROR", "Endpoint required")
		return
	}
	if !validEndpoint(p.Endpoint) {
		sendWSError(conn, id, "VALIDATION_ERROR", "Invalid endpoint")
		return
	}

	nodeID, userID := lookupNodeForAgent(agent.ID)
	if nodeID == 0 {
		sendWSError(conn, id, "NOT_NODE", "Agent not associated with a node")
		return
	}

	// Only update if endpoint was not manually set
	result, err := store.Exec(
		"UPDATE user_node SET wg_endpoint = ?, wg_endpoint_source = 'stun', updated_at = datetime('now') WHERE id = ? AND wg_endpoint_source != 'manual'",
		p.Endpoint, nodeID,
	)
	if err != nil {
		sendWSError(conn, id, "INTERNAL_ERROR", "Failed to update endpoint")
		return
	}

	rows, _ := result.RowsAffected()
	sendWSResult(conn, id, "endpoint.discovered", map[string]any{
		"updated": rows > 0,
	})

	if rows > 0 {
		log.Printf("endpoint.discovered: node=%d endpoint=%s", nodeID, p.Endpoint)
		go notifyNodeSync(userID)
	}
}

// handleKeyRotate processes a key rotation request from an agent.
func handleKeyRotate(conn *wsConn, agent *AgentPrincipal, id string, payload json.RawMessage) {
	var p struct {
		PublicKey string `json:"public_key"`
	}
	if json.Unmarshal(payload, &p) != nil || p.PublicKey == "" {
		sendWSError(conn, id, "VALIDATION_ERROR", "Public key required")
		return
	}
	if !validWGPubkey(p.PublicKey) {
		sendWSError(conn, id, "VALIDATION_ERROR", "Invalid WireGuard public key")
		return
	}

	nodeID, userID := lookupNodeForAgent(agent.ID)
	if nodeID == 0 {
		sendWSError(conn, id, "NOT_NODE", "Agent not associated with a node")
		return
	}

	_, err := store.Exec(
		"UPDATE user_node SET wg_pubkey = ?, updated_at = datetime('now') WHERE id = ?",
		p.PublicKey, nodeID,
	)
	if err != nil {
		sendWSError(conn, id, "INTERNAL_ERROR", "Failed to update public key")
		return
	}

	emitEvent("node.key_rotated", "", 0, "", 200, map[string]any{
		"node_id": nodeID, "agent": agent.Name,
	})

	sendWSResult(conn, id, "key.rotate", map[string]any{
		"success": true,
	})

	log.Printf("key.rotate: node=%d agent=%s", nodeID, agent.Name)
	go notifyNodeSync(userID)
}

// handleRelayBind processes a relay binding request.
func handleRelayBind(conn *wsConn, id string, nodeID, userID int, payload json.RawMessage) {
	var p struct {
		PeerNodeID int `json:"peer_node_id"`
	}
	if json.Unmarshal(payload, &p) != nil || p.PeerNodeID == 0 {
		sendWSError(conn, id, "VALIDATION_ERROR", "peer_node_id required")
		return
	}

	ok := registerRelayBinding(nodeID, p.PeerNodeID, userID)
	sendWSResult(conn, id, "relay.bind", map[string]any{
		"success": ok,
	})
}

// handleRelayUnbind processes a relay unbind request.
func handleRelayUnbind(nodeID int, payload json.RawMessage) {
	var p struct {
		PeerNodeID int `json:"peer_node_id"`
	}
	if json.Unmarshal(payload, &p) != nil || p.PeerNodeID == 0 {
		return
	}
	unregisterRelayBinding(nodeID, p.PeerNodeID)
}

// --- WS helpers ---

func sendWSResult(conn *wsConn, id, typ string, payload any) {
	msg := map[string]any{"type": typ + ".result", "payload": payload}
	if id != "" {
		msg["id"] = id
	}
	b, _ := json.Marshal(msg)
	conn.safeWrite(websocket.TextMessage, b)
}

func sendWSError(conn *wsConn, id, code, message string) {
	msg := map[string]any{"type": "error", "code": code, "message": message}
	if id != "" {
		msg["id"] = id
	}
	b, _ := json.Marshal(msg)
	conn.safeWrite(websocket.TextMessage, b)
}

func closeWSAgent(conn *wsConn, code int, reason string) {
	msg := websocket.FormatCloseMessage(code, reason)
	conn.safeWriteControl(websocket.CloseMessage, msg, time.Now().Add(time.Second))
	conn.Close()
}
