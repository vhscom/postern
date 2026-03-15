package main

import (
	"encoding/binary"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Relay rate limiting: 10 MB per minute per node
const (
	relayByteRateWindow = 60 * time.Second
	relayByteRateMax    = 10 * 1024 * 1024
)

// relayState holds per-node relay state and byte-rate tracking.
type relayState struct {
	peerNodeIDs []int // bound peer node IDs
	byteCount   int
	windowStart time.Time
}

var relayRouter struct {
	mu     sync.RWMutex
	byNode map[int]*relayState // keyed by source node ID
}

func init() {
	relayRouter.byNode = make(map[int]*relayState)
}

// registerRelayBinding records that sourceNodeID wants to relay through peerNodeID.
func registerRelayBinding(sourceNodeID, peerNodeID, userID int) bool {
	// Validate both nodes belong to the same user
	nodeRegistry.mu.RLock()
	sourceNode := nodeRegistry.byID[sourceNodeID]
	peerNode := nodeRegistry.byID[peerNodeID]
	nodeRegistry.mu.RUnlock()

	if sourceNode == nil || peerNode == nil {
		return false
	}
	if sourceNode.userID != peerNode.userID || sourceNode.userID != userID {
		return false
	}

	relayRouter.mu.Lock()
	defer relayRouter.mu.Unlock()

	state, ok := relayRouter.byNode[sourceNodeID]
	if !ok {
		state = &relayState{windowStart: time.Now()}
		relayRouter.byNode[sourceNodeID] = state
	}

	// Avoid duplicate bindings
	for _, id := range state.peerNodeIDs {
		if id == peerNodeID {
			return true
		}
	}

	state.peerNodeIDs = append(state.peerNodeIDs, peerNodeID)
	slog.Info("relay bound", "source", sourceNodeID, "peer", peerNodeID)
	return true
}

// unregisterRelayBinding removes a specific relay binding.
func unregisterRelayBinding(sourceNodeID, peerNodeID int) {
	relayRouter.mu.Lock()
	defer relayRouter.mu.Unlock()

	state, ok := relayRouter.byNode[sourceNodeID]
	if !ok {
		return
	}

	for i, id := range state.peerNodeIDs {
		if id == peerNodeID {
			state.peerNodeIDs = append(state.peerNodeIDs[:i], state.peerNodeIDs[i+1:]...)
			break
		}
	}

	if len(state.peerNodeIDs) == 0 {
		delete(relayRouter.byNode, sourceNodeID)
	}
}

// cleanupRelayBindings removes all relay state for a node (called on disconnect).
func cleanupRelayBindings(nodeID int) {
	relayRouter.mu.Lock()
	defer relayRouter.mu.Unlock()
	delete(relayRouter.byNode, nodeID)
}

// handleRelayPacket routes a binary frame from sourceNodeID to the destination.
// Binary frame format: [4-byte destNodeID][raw WireGuard packet]
func handleRelayPacket(sourceNodeID int, raw []byte) {
	if len(raw) < 5 {
		return
	}

	destNodeID := int(binary.BigEndian.Uint32(raw[0:4]))

	// Rate limit check
	relayRouter.mu.Lock()
	state, ok := relayRouter.byNode[sourceNodeID]
	if !ok {
		relayRouter.mu.Unlock()
		return
	}

	now := time.Now()
	if now.Sub(state.windowStart) > relayByteRateWindow {
		state.windowStart = now
		state.byteCount = 0
	}
	state.byteCount += len(raw)
	if state.byteCount > relayByteRateMax {
		relayRouter.mu.Unlock()
		return // silently drop
	}

	// Verify binding exists
	bound := false
	for _, id := range state.peerNodeIDs {
		if id == destNodeID {
			bound = true
			break
		}
	}
	relayRouter.mu.Unlock()

	if !bound {
		return
	}

	// Look up destination node's connection
	nodeRegistry.mu.RLock()
	destNode := nodeRegistry.byID[destNodeID]
	nodeRegistry.mu.RUnlock()

	if destNode == nil {
		return
	}

	// Rewrite header: swap dest nodeID with source nodeID for return routing
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(sourceNodeID))
	packet := append(header, raw[4:]...)

	destNode.conn.safeWrite(websocket.BinaryMessage, packet)
}
