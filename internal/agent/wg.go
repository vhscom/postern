package agent

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// peerConfig is the desired state for a single WireGuard peer.
type peerConfig struct {
	Label               string `json:"label,omitempty"`
	PublicKey           string `json:"public_key"`
	Endpoint            string `json:"endpoint,omitempty"`
	AllowedIPs          string `json:"allowed_ips"`
	PersistentKeepalive int    `json:"persistent_keepalive,omitempty"`
}

// interfaceStatus is the current state of a WireGuard interface.
type interfaceStatus struct {
	Interface  string       `json:"interface"`
	PublicKey  string       `json:"public_key"`
	ListenPort int          `json:"listen_port"`
	Peers      []peerStatus `json:"peers"`
}

// peerStatus is the live state of a single WireGuard peer.
type peerStatus struct {
	PublicKey           string `json:"public_key"`
	Endpoint            string `json:"endpoint,omitempty"`
	AllowedIPs          string `json:"allowed_ips,omitempty"`
	LatestHandshake     int64  `json:"latest_handshake"`
	TransferRx          int64  `json:"transfer_rx"`
	TransferTx          int64  `json:"transfer_tx"`
	PersistentKeepalive int    `json:"persistent_keepalive,omitempty"`
}

// wgShow parses "wg show <iface> dump" into structured data.
func wgShow(iface string) (*interfaceStatus, error) {
	out, err := exec.Command("wg", "show", iface, "dump").Output()
	if err != nil {
		return nil, fmt.Errorf("wg show %s dump: %w", iface, err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("wg show: empty output")
	}

	// First line: private-key, public-key, listen-port, fwmark
	ifields := strings.Split(lines[0], "\t")
	if len(ifields) < 3 {
		return nil, fmt.Errorf("wg show: unexpected interface line format")
	}

	port, _ := strconv.Atoi(ifields[2])
	status := &interfaceStatus{
		Interface:  iface,
		PublicKey:  ifields[1],
		ListenPort: port,
	}

	// Remaining lines: peer entries
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)
		keepalive, _ := strconv.Atoi(fields[7])

		status.Peers = append(status.Peers, peerStatus{
			PublicKey:           fields[0],
			Endpoint:            fields[2],
			AllowedIPs:          fields[3],
			LatestHandshake:     handshake,
			TransferRx:          rx,
			TransferTx:          tx,
			PersistentKeepalive: keepalive,
		})
	}

	return status, nil
}

// wgSetPeer adds or updates a single peer.
func wgSetPeer(iface string, peer peerConfig) error {
	args := []string{"set", iface, "peer", peer.PublicKey}
	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}
	if peer.AllowedIPs != "" {
		args = append(args, "allowed-ips", peer.AllowedIPs)
	}
	if peer.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.PersistentKeepalive))
	}

	out, err := exec.Command("wg", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set peer %s: %w: %s", peer.PublicKey[:8], err, out)
	}
	return nil
}

// wgRemovePeer removes a peer from the interface.
func wgRemovePeer(iface, pubkey string) error {
	out, err := exec.Command("wg", "set", iface, "peer", pubkey, "remove").CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg remove peer %s: %w: %s", pubkey[:8], err, out)
	}
	return nil
}

// wgSyncFull ensures the interface has exactly the desired set of peers.
func wgSyncFull(iface string, desired []peerConfig) error {
	current, err := wgShow(iface)
	if err != nil {
		// Interface might not exist yet or wg not available; try setting peers directly
		for _, p := range desired {
			if err := wgSetPeer(iface, p); err != nil {
				return err
			}
		}
		return nil
	}

	// Build desired set keyed by public key
	want := map[string]peerConfig{}
	for _, p := range desired {
		want[p.PublicKey] = p
	}

	// Remove peers not in desired set
	for _, p := range current.Peers {
		if _, ok := want[p.PublicKey]; !ok {
			if err := wgRemovePeer(iface, p.PublicKey); err != nil {
				return err
			}
		}
	}

	// Add/update desired peers
	for _, p := range desired {
		if err := wgSetPeer(iface, p); err != nil {
			return err
		}
	}

	return nil
}
