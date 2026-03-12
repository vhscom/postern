package main

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type connectedNode struct {
	conn    *wsConn
	agentID int
	userID  int
	nodeID  int
	label   string
}

var nodes struct {
	mu   sync.RWMutex
	byID map[int]*connectedNode // keyed by node ID
}

func init() {
	nodes.byID = make(map[int]*connectedNode)
}

// registerNode adds a node agent to the connected registry.
func registerNode(n *connectedNode) {
	nodes.mu.Lock()
	defer nodes.mu.Unlock()
	nodes.byID[n.nodeID] = n
}

// unregisterNode removes a node agent from the registry.
func unregisterNode(nodeID int) {
	nodes.mu.Lock()
	defer nodes.mu.Unlock()
	delete(nodes.byID, nodeID)
}

// notifyNodeSync pushes the full peer set to all connected nodes for a user.
// Called after peer upsert/delete. Excludes each node's own pubkey from its peer list.
func notifyNodeSync(userID int) {
	nodes.mu.RLock()
	var targets []*connectedNode
	for _, n := range nodes.byID {
		if n.userID == userID {
			targets = append(targets, n)
		}
	}
	nodes.mu.RUnlock()

	if len(targets) == 0 {
		return
	}

	// Fetch all peers for this user
	rows, err := store.Query(
		"SELECT wg_pubkey, endpoint, allowed_ips, persistent_keepalive FROM user_peer WHERE user_id = ?",
		userID,
	)
	if err != nil {
		log.Printf("notifyNodeSync: query peers: %v", err)
		return
	}
	defer rows.Close()

	type peer struct {
		Pubkey     string `json:"public_key"`
		Endpoint   string `json:"endpoint"`
		AllowedIPs string `json:"allowed_ips"`
		Keepalive  int    `json:"persistent_keepalive,omitempty"`
	}
	var allPeers []peer
	for rows.Next() {
		var p peer
		rows.Scan(&p.Pubkey, &p.Endpoint, &p.AllowedIPs, &p.Keepalive)
		allPeers = append(allPeers, p)
	}

	// Fetch each node's own pubkey to exclude
	for _, target := range targets {
		var nodePubkey string
		store.QueryRow("SELECT wg_pubkey FROM user_node WHERE id = ?", target.nodeID).Scan(&nodePubkey)

		// Filter out the node's own pubkey
		var filtered []peer
		for _, p := range allPeers {
			if p.Pubkey != nodePubkey {
				filtered = append(filtered, p)
			}
		}
		if filtered == nil {
			filtered = []peer{}
		}

		msg := map[string]any{
			"type": "wg.sync",
			"payload": map[string]any{
				"action": "full_sync",
				"peers":  filtered,
			},
		}
		data, _ := json.Marshal(msg)
		target.conn.safeWrite(websocket.TextMessage, data)
	}
}

// lookupNodeForAgent returns the node ID and user ID for an agent credential,
// or 0, 0 if the agent is not associated with a node.
func lookupNodeForAgent(agentID int) (nodeID, userID int) {
	store.QueryRow(
		"SELECT n.id, n.user_id FROM user_node n WHERE n.agent_credential_id = ?",
		agentID,
	).Scan(&nodeID, &userID)
	return
}

// handleWGStatus processes a wg.status message from a node agent.
func handleWGStatus(agent *AgentPrincipal, payload json.RawMessage) {
	nodeID, _ := lookupNodeForAgent(agent.ID)
	if nodeID == 0 {
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	store.Exec(
		"UPDATE user_node SET last_status = ?, last_seen_at = ?, updated_at = ? WHERE id = ?",
		string(payload), now, now, nodeID,
	)
}
