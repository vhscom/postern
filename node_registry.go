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
}

var nodeRegistry struct {
	mu   sync.RWMutex
	byID map[int]*connectedNode // keyed by node ID
}

func init() {
	nodeRegistry.byID = make(map[int]*connectedNode)
}

func registerNode(n *connectedNode) {
	nodeRegistry.mu.Lock()
	defer nodeRegistry.mu.Unlock()
	nodeRegistry.byID[n.nodeID] = n
}

func unregisterNode(nodeID int) {
	nodeRegistry.mu.Lock()
	defer nodeRegistry.mu.Unlock()
	delete(nodeRegistry.byID, nodeID)
}

// notifyNodeSync pushes the mesh peer set to all connected nodes for a user.
// Each node gets every OTHER node as a WireGuard peer. Nodes are the mesh.
func notifyNodeSync(userID int) {
	nodeRegistry.mu.RLock()
	var targets []*connectedNode
	for _, n := range nodeRegistry.byID {
		if n.userID == userID {
			targets = append(targets, n)
		}
	}
	nodeRegistry.mu.RUnlock()

	if len(targets) == 0 {
		return
	}

	// Fetch all nodes for this user — these form the mesh
	type meshNode struct {
		ID         int
		Label      string
		Pubkey     string
		Endpoint   *string
		AllowedIPs string
		ListenPort int
		Keepalive  int
	}
	rows, err := store.Query(
		"SELECT id, label, wg_pubkey, wg_endpoint, allowed_ips, wg_listen_port, persistent_keepalive FROM user_node WHERE user_id = ?",
		userID,
	)
	if err != nil {
		log.Printf("notifyNodeSync: query nodes: %v", err)
		return
	}
	defer rows.Close()

	var allNodes []meshNode
	for rows.Next() {
		var n meshNode
		rows.Scan(&n.ID, &n.Label, &n.Pubkey, &n.Endpoint, &n.AllowedIPs, &n.ListenPort, &n.Keepalive)
		allNodes = append(allNodes, n)
	}

	// Each connected node gets its own info (self) plus all OTHER nodes as peers
	type syncPeer struct {
		NodeID     int    `json:"node_id"`
		Label      string `json:"label,omitempty"`
		PublicKey  string `json:"public_key"`
		Endpoint   string `json:"endpoint,omitempty"`
		AllowedIPs string `json:"allowed_ips"`
		Keepalive  int    `json:"persistent_keepalive,omitempty"`
	}
	type syncSelf struct {
		NodeID     int    `json:"node_id"`
		MeshIP     string `json:"mesh_ip"`
		ListenPort int    `json:"listen_port"`
	}

	for _, target := range targets {
		var peers []syncPeer
		var self *syncSelf
		for _, n := range allNodes {
			if n.ID == target.nodeID {
				self = &syncSelf{
					NodeID:     n.ID,
					MeshIP:     n.AllowedIPs,
					ListenPort: n.ListenPort,
				}
				continue // skip self from peer list
			}
			ep := ""
			if n.Endpoint != nil {
				ep = *n.Endpoint
			}
			peers = append(peers, syncPeer{
				NodeID:     n.ID,
				Label:      n.Label,
				PublicKey:  n.Pubkey,
				Endpoint:   ep,
				AllowedIPs: n.AllowedIPs,
				Keepalive:  n.Keepalive,
			})
		}
		if peers == nil {
			peers = []syncPeer{}
		}

		msg := map[string]any{
			"type": "wg.sync",
			"payload": map[string]any{
				"action": "full_sync",
				"self":   self,
				"peers":  peers,
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
