package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// relayState represents a peer's relay state machine position.
type relayState int

const (
	relayDirectAttempt relayState = iota
	relayBinding
	relayActive
	relayDirect
)

const (
	relayDirectTimeout = 30 * time.Second
	relayHandshakeMax  = 120 // seconds — consider stale if older
)

// peerRelay manages the relay path for a single unreachable peer.
type peerRelay struct {
	pubkey   string
	nodeID   int
	state    relayState
	listener *net.UDPConn
	cancel   context.CancelFunc
	started  time.Time
}

// relayManager owns per-peer relay state and routes binary frames.
type relayManager struct {
	mu         sync.Mutex
	peers      map[string]*peerRelay // keyed by pubkey
	conn       *websocket.Conn
	iface      string
	wgPort     int
	nodeMap    map[string]int // pubkey → nodeID
	injectConn *net.UDPConn   // reusable conn for injecting packets to local WG
	ctx        context.Context
	cancelFn   context.CancelFunc
}

func newRelayManager(ctx context.Context, conn *websocket.Conn, iface string, wgPort int) *relayManager {
	rctx, cancel := context.WithCancel(ctx)
	return &relayManager{
		peers:    make(map[string]*peerRelay),
		conn:     conn,
		iface:    iface,
		wgPort:   wgPort,
		nodeMap:  make(map[string]int),
		ctx:      rctx,
		cancelFn: cancel,
	}
}

func (rm *relayManager) close() {
	rm.cancelFn()
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for _, pr := range rm.peers {
		if pr.cancel != nil {
			pr.cancel()
		}
		if pr.listener != nil {
			pr.listener.Close()
		}
	}
	rm.peers = make(map[string]*peerRelay)
	if rm.injectConn != nil {
		rm.injectConn.Close()
		rm.injectConn = nil
	}
}

// updateNodeMap sets the pubkey→nodeID mapping from sync data.
func (rm *relayManager) updateNodeMap(m map[string]int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.nodeMap = m
}

// evaluatePeers checks handshake status and starts/stops relays as needed.
func (rm *relayManager) evaluatePeers(status *interfaceStatus) {
	if status == nil {
		return
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	now := time.Now()
	activePubkeys := map[string]bool{}

	for _, peer := range status.Peers {
		activePubkeys[peer.PublicKey] = true
		nodeID, ok := rm.nodeMap[peer.PublicKey]
		if !ok {
			continue
		}

		pr, exists := rm.peers[peer.PublicKey]
		handshakeStale := peer.LatestHandshake == 0 ||
			now.Unix()-peer.LatestHandshake > relayHandshakeMax

		if !handshakeStale {
			// Peer is reachable directly — tear down relay if active
			if exists && pr.state != relayDirect {
				log.Printf("relay: peer %s reachable directly, tearing down relay", peer.PublicKey[:8])
				rm.stopRelay(peer.PublicKey)
			}
			continue
		}

		if !exists {
			// Start direct attempt timer
			rm.peers[peer.PublicKey] = &peerRelay{
				pubkey:  peer.PublicKey,
				nodeID:  nodeID,
				state:   relayDirectAttempt,
				started: now,
			}
			continue
		}

		switch pr.state {
		case relayDirectAttempt:
			if now.Sub(pr.started) > relayDirectTimeout {
				// Direct attempt expired — start relay
				rm.startRelay(pr)
			}
		case relayDirect:
			// Was direct but handshake is now stale — restart attempt
			pr.state = relayDirectAttempt
			pr.started = now
		}
	}

	// Clean up relays for peers no longer in the mesh
	for pubkey := range rm.peers {
		if !activePubkeys[pubkey] {
			rm.stopRelay(pubkey)
		}
	}
}

// startRelay sets up the local UDP proxy and sends relay.bind.
func (rm *relayManager) startRelay(pr *peerRelay) {
	pr.state = relayBinding

	laddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	listener, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		log.Printf("relay: listen failed for %s: %v", pr.pubkey[:8], err)
		return
	}
	pr.listener = listener

	localPort := listener.LocalAddr().(*net.UDPAddr).Port

	// Set WireGuard peer endpoint to our local proxy
	if err := wgSetPeer(rm.iface, peerConfig{
		PublicKey: pr.pubkey,
		Endpoint:  fmt.Sprintf("127.0.0.1:%d", localPort),
	}); err != nil {
		log.Printf("relay: set peer endpoint failed for %s: %v", pr.pubkey[:8], err)
		listener.Close()
		return
	}

	// Send relay.bind to server
	bind := map[string]any{
		"type": "relay.bind",
		"payload": map[string]any{
			"peer_node_id": pr.nodeID,
		},
	}
	data, _ := json.Marshal(bind)
	if err := rm.conn.Write(rm.ctx, websocket.MessageText, data); err != nil {
		log.Printf("relay: bind send failed for %s: %v", pr.pubkey[:8], err)
		listener.Close()
		return
	}

	ctx, cancel := context.WithCancel(rm.ctx)
	pr.cancel = cancel
	pr.state = relayActive

	log.Printf("relay: started for peer %s via 127.0.0.1:%d", pr.pubkey[:8], localPort)

	// UDP → WebSocket goroutine
	go rm.udpToWS(ctx, listener, pr.nodeID)

	// WebSocket → UDP is handled by handleBinaryFrame dispatching to injectPacket
}

func (rm *relayManager) stopRelay(pubkey string) {
	pr, ok := rm.peers[pubkey]
	if !ok {
		return
	}
	if pr.cancel != nil {
		pr.cancel()
	}
	if pr.listener != nil {
		pr.listener.Close()
	}
	delete(rm.peers, pubkey)

	// Send relay.unbind
	unbind := map[string]any{
		"type": "relay.unbind",
		"payload": map[string]any{
			"peer_node_id": pr.nodeID,
		},
	}
	data, _ := json.Marshal(unbind)
	rm.conn.Write(rm.ctx, websocket.MessageText, data)
}

// udpToWS reads UDP packets from the local listener and forwards them
// as binary WebSocket frames with a 4-byte nodeID header.
func (rm *relayManager) udpToWS(ctx context.Context, listener *net.UDPConn, destNodeID int) {
	buf := make([]byte, 4+65536) // 4-byte header + max UDP
	binary.BigEndian.PutUint32(buf[0:4], uint32(destNodeID))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		listener.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := listener.ReadFromUDP(buf[4:])
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}

		if err := rm.conn.Write(ctx, websocket.MessageBinary, buf[:4+n]); err != nil {
			return
		}
	}
}

// injectPacket writes a received relay packet to the local WireGuard port.
func (rm *relayManager) injectPacket(data []byte) {
	if len(data) < 5 { // at least header + 1 byte
		return
	}

	rm.mu.Lock()
	if rm.injectConn == nil {
		wgAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rm.wgPort}
		c, err := net.DialUDP("udp4", nil, wgAddr)
		if err != nil {
			rm.mu.Unlock()
			return
		}
		rm.injectConn = c
	}
	c := rm.injectConn
	rm.mu.Unlock()

	// Strip 4-byte source nodeID header, send raw WG packet
	c.Write(data[4:])
}
