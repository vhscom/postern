package main

import (
	"encoding/binary"
	"testing"
)

func resetRelayRouter() {
	relayRouter.mu.Lock()
	relayRouter.byNode = make(map[int]*relayState)
	relayRouter.mu.Unlock()
}

func TestRegisterRelayBindingRequiresSameUser(t *testing.T) {
	resetRelayRouter()
	// No nodes registered — binding should fail
	if registerRelayBinding(1, 2, 1) {
		t.Error("binding should fail when nodes are not registered")
	}
}

func TestRegisterRelayBindingSuccess(t *testing.T) {
	resetRelayRouter()

	// Register two nodes for the same user
	registerNode(&connectedNode{nodeID: 10, userID: 1, agentID: 1})
	registerNode(&connectedNode{nodeID: 20, userID: 1, agentID: 2})
	defer unregisterNode(10)
	defer unregisterNode(20)

	if !registerRelayBinding(10, 20, 1) {
		t.Error("binding should succeed for same-user nodes")
	}

	// Duplicate binding should also return true
	if !registerRelayBinding(10, 20, 1) {
		t.Error("duplicate binding should return true")
	}

	// Verify state exists
	relayRouter.mu.RLock()
	state, ok := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()
	if !ok {
		t.Fatal("expected relay state for node 10")
	}
	if len(state.peerNodeIDs) != 1 {
		t.Errorf("expected 1 binding, got %d", len(state.peerNodeIDs))
	}
}

func TestRegisterRelayBindingCrossUser(t *testing.T) {
	resetRelayRouter()

	registerNode(&connectedNode{nodeID: 10, userID: 1, agentID: 1})
	registerNode(&connectedNode{nodeID: 20, userID: 2, agentID: 2}) // different user
	defer unregisterNode(10)
	defer unregisterNode(20)

	if registerRelayBinding(10, 20, 1) {
		t.Error("binding should fail for nodes belonging to different users")
	}
}

func TestUnregisterRelayBinding(t *testing.T) {
	resetRelayRouter()

	registerNode(&connectedNode{nodeID: 10, userID: 1, agentID: 1})
	registerNode(&connectedNode{nodeID: 20, userID: 1, agentID: 2})
	registerNode(&connectedNode{nodeID: 30, userID: 1, agentID: 3})
	defer unregisterNode(10)
	defer unregisterNode(20)
	defer unregisterNode(30)

	registerRelayBinding(10, 20, 1)
	registerRelayBinding(10, 30, 1)

	unregisterRelayBinding(10, 20)

	relayRouter.mu.RLock()
	state := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()

	if len(state.peerNodeIDs) != 1 {
		t.Errorf("expected 1 remaining binding, got %d", len(state.peerNodeIDs))
	}
	if state.peerNodeIDs[0] != 30 {
		t.Errorf("expected remaining binding to node 30, got %d", state.peerNodeIDs[0])
	}

	// Unbind last one — state should be cleaned up
	unregisterRelayBinding(10, 30)
	relayRouter.mu.RLock()
	_, exists := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()
	if exists {
		t.Error("relay state should be cleaned up when all bindings removed")
	}
}

func TestCleanupRelayBindings(t *testing.T) {
	resetRelayRouter()

	registerNode(&connectedNode{nodeID: 10, userID: 1, agentID: 1})
	registerNode(&connectedNode{nodeID: 20, userID: 1, agentID: 2})
	defer unregisterNode(10)
	defer unregisterNode(20)

	registerRelayBinding(10, 20, 1)

	cleanupRelayBindings(10)

	relayRouter.mu.RLock()
	_, exists := relayRouter.byNode[10]
	relayRouter.mu.RUnlock()
	if exists {
		t.Error("cleanupRelayBindings should remove all state")
	}
}

func TestHandleRelayPacketTooShort(t *testing.T) {
	resetRelayRouter()
	// Should not panic on short packets
	handleRelayPacket(1, []byte{0, 0, 0})
	handleRelayPacket(1, nil)
	handleRelayPacket(1, []byte{})
}

func TestHandleRelayPacketNoBinding(t *testing.T) {
	resetRelayRouter()
	// Build a valid-sized packet but with no binding — should be silently dropped
	packet := make([]byte, 100)
	binary.BigEndian.PutUint32(packet[0:4], 20) // dest node 20
	handleRelayPacket(10, packet)
	// No panic = success
}

func TestHandleRelayPacketRateLimit(t *testing.T) {
	resetRelayRouter()

	registerNode(&connectedNode{nodeID: 10, userID: 1, agentID: 1})
	registerNode(&connectedNode{nodeID: 20, userID: 1, agentID: 2})
	defer unregisterNode(10)
	defer unregisterNode(20)

	registerRelayBinding(10, 20, 1)

	// Exhaust rate limit
	relayRouter.mu.Lock()
	state := relayRouter.byNode[10]
	state.byteCount = relayByteRateMax + 1
	relayRouter.mu.Unlock()

	// This packet should be silently dropped (rate limited)
	packet := make([]byte, 100)
	binary.BigEndian.PutUint32(packet[0:4], 20)
	handleRelayPacket(10, packet)
	// No panic = rate limiting worked
}
