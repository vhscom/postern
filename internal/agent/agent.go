package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/coder/websocket"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
	headingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	cmdStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	flagStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

type config struct {
	Server    string `json:"server"`
	Token     string `json:"token"`
	Interface string `json:"interface"`
}

// Run is the entry point for "postern agent".
func Run() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			runInit()
			return
		case "install":
			runInstall()
			return
		case "uninstall":
			runUninstall()
			return
		case "--help", "-h", "help":
			printAgentHelp()
			return
		}
	}

	cfg := loadConfig()
	log.Printf("postern agent: server=%s interface=%s", cfg.Server, cfg.Interface)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	connectLoop(ctx, cfg)
}

func printAgentHelp() {
	title := func(n, t string) { fmt.Printf("%s %s\n\n", titleStyle.Render(n), dimStyle.Render("— "+t)) }
	heading := func(s string) { fmt.Printf("%s\n", headingStyle.Render(s)) }
	cmd := func(c, d string) {
		fmt.Printf("  %s  %s\n", cmdStyle.Render(fmt.Sprintf("%-42s", c)), dimStyle.Render(d))
	}
	env := func(n, d string) {
		fmt.Printf("  %s  %s\n", flagStyle.Render(fmt.Sprintf("%-28s", n)), dimStyle.Render(d))
	}

	title("postern agent", "WireGuard mesh agent")
	heading("Usage")
	cmd("postern agent", "Connect and sync WireGuard config")
	cmd("postern agent init <server> <key> [iface]", "Write config from server URL and API key")
	cmd("postern agent install", "Install as system service (launchd/systemd)")
	cmd("postern agent uninstall", "Remove system service")
	fmt.Println()
	heading("Environment")
	env("POSTERN_AGENT_SERVER", "Server URL (overrides config file)")
	env("POSTERN_AGENT_TOKEN", "API key (overrides config file)")
	env("POSTERN_AGENT_INTERFACE", "WireGuard interface (default: wg0)")
	env("POSTERN_AGENT_CONFIG_DIR", "Config directory (default: ~/.config/postern)")
}

func runInit() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: postern agent init <server-url> <api-key> [interface]\n")
		fmt.Fprintf(os.Stderr, "Example: postern agent init https://postern.example.com abc123 wg0\n")
		os.Exit(1)
	}

	iface := "wg0"
	if len(os.Args) > 4 {
		iface = os.Args[4]
	}

	cfg := config{
		Server:    os.Args[2],
		Token:     os.Args[3],
		Interface: iface,
	}

	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Failed to create config dir: %v", err)
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.Fatalf("Failed to write config: %v", err)
	}
	fmt.Printf("Config written to %s\n", path)
	fmt.Printf("Run 'postern agent' to connect.\n")
}

func configDir() string {
	if d := os.Getenv("POSTERN_AGENT_CONFIG_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "postern")
}

func loadConfig() *config {
	// CLI env overrides
	server := os.Getenv("POSTERN_AGENT_SERVER")
	token := os.Getenv("POSTERN_AGENT_TOKEN")
	iface := os.Getenv("POSTERN_AGENT_INTERFACE")

	if server != "" && token != "" {
		if iface == "" {
			iface = "wg0"
		}
		return &config{Server: server, Token: token, Interface: iface}
	}

	// Config file
	path := filepath.Join(configDir(), "config.json")
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "No config found. Run 'postern agent init <server> <key>' first.\n")
		os.Exit(1)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}
	if cfg.Interface == "" {
		cfg.Interface = "wg0"
	}
	return &cfg
}

func connectLoop(ctx context.Context, cfg *config) {
	backoff := time.Second

	for {
		err := runSession(ctx, cfg)
		if ctx.Err() != nil {
			log.Printf("shutting down")
			return
		}

		if err != nil {
			log.Printf("disconnected: %v", err)
		}

		log.Printf("reconnecting in %s...", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}
	}
}

func runSession(ctx context.Context, cfg *config) error {
	wsURL := cfg.Server + "/ops/ws"
	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: map[string][]string{
			"Authorization": {"Bearer " + cfg.Token},
		},
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.CloseNow()

	log.Printf("connected to %s", cfg.Server)

	// Negotiate capabilities
	capReq := map[string]any{
		"type":         "capability.request",
		"capabilities": []string{"wg_sync", "wg_status", "endpoint_discovery", "key_rotate"},
	}
	data, _ := json.Marshal(capReq)
	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		return fmt.Errorf("capability request: %w", err)
	}

	// Read capability.granted
	_, resp, err := conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("capability response: %w", err)
	}

	var granted struct {
		Type    string   `json:"type"`
		Granted []string `json:"granted"`
	}
	if err := json.Unmarshal(resp, &granted); err != nil {
		return fmt.Errorf("parse capabilities: %w", err)
	}

	caps := map[string]bool{}
	for _, c := range granted.Granted {
		caps[c] = true
	}
	log.Printf("capabilities: %v", granted.Granted)

	if !caps["wg_sync"] {
		return fmt.Errorf("server did not grant wg_sync capability")
	}

	// Send initial status
	status, err := wgShow(cfg.Interface)
	if err != nil {
		log.Printf("warning: could not read wg interface %s: %v", cfg.Interface, err)
	} else {
		sendStatus(ctx, conn, status)
	}

	// STUN endpoint discovery
	if caps["endpoint_discovery"] {
		go sendEndpointDiscovery(ctx, conn, getListenPort(status))
	}

	// Relay manager
	rm := newRelayManager(ctx, conn, cfg.Interface, getListenPort(status))
	defer rm.close()

	// Main loop: read server messages, report status periodically
	statusTicker := time.NewTicker(60 * time.Second)
	defer statusTicker.Stop()

	stunTicker := time.NewTicker(30 * time.Minute)
	defer stunTicker.Stop()

	keyRotateTicker := time.NewTicker(1 * time.Hour)
	defer keyRotateTicker.Stop()

	msgCh := make(chan wsMessage, 16)
	errCh := make(chan error, 1)

	go func() {
		for {
			msgType, data, err := conn.Read(ctx)
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- wsMessage{msgType: msgType, data: data}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "shutdown")
			return nil
		case err := <-errCh:
			return err
		case msg := <-msgCh:
			if msg.msgType == websocket.MessageBinary {
				// Relay packet from server — inject to local WireGuard
				rm.injectPacket(msg.data)
				continue
			}
			if err := handleMessage(ctx, conn, cfg.Interface, msg.data, rm); err != nil {
				log.Printf("handle message: %v", err)
			}
		case <-statusTicker.C:
			status, err := wgShow(cfg.Interface)
			if err != nil {
				log.Printf("wg show: %v", err)
				continue
			}
			sendStatus(ctx, conn, status)
			// Evaluate relay needs
			rm.evaluatePeers(status)
		case <-stunTicker.C:
			if caps["endpoint_discovery"] {
				listenPort := 51820
				if s, err := wgShow(cfg.Interface); err == nil {
					listenPort = getListenPort(s)
				}
				sendEndpointDiscovery(ctx, conn, listenPort)
			}
		case <-keyRotateTicker.C:
			if caps["key_rotate"] && needsRotation() {
				if err := rotateKey(ctx, conn, cfg.Interface); err != nil {
					log.Printf("key rotation failed: %v", err)
				}
			}
		}
	}
}

// wsMessage pairs a WebSocket message type with its payload.
type wsMessage struct {
	msgType websocket.MessageType
	data    []byte
}

func sendEndpointDiscovery(ctx context.Context, conn *websocket.Conn, listenPort int) {
	ep, err := discoverEndpoint(ctx, listenPort)
	if err != nil {
		log.Printf("STUN discovery failed: %v", err)
		return
	}
	log.Printf("STUN discovered endpoint: %s", ep)
	msg := map[string]any{
		"type": "endpoint.discovered",
		"payload": map[string]any{
			"endpoint": ep,
		},
	}
	data, _ := json.Marshal(msg)
	conn.Write(ctx, websocket.MessageText, data)
}

func getListenPort(status *interfaceStatus) int {
	if status != nil && status.ListenPort > 0 {
		return status.ListenPort
	}
	return 51820
}

func sendStatus(ctx context.Context, conn *websocket.Conn, status *interfaceStatus) {
	msg := map[string]any{
		"type":    "wg.status",
		"payload": status,
	}
	data, _ := json.Marshal(msg)
	conn.Write(ctx, websocket.MessageText, data)
}

func handleMessage(ctx context.Context, conn *websocket.Conn, iface string, raw []byte, rm *relayManager) error {
	var msg struct {
		Type    string          `json:"type"`
		ID      string          `json:"id"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil // ignore unparseable
	}

	switch msg.Type {
	case "heartbeat", "pong":
		// no-op
	case "wg.sync":
		return handleSync(ctx, conn, iface, msg.ID, msg.Payload, rm)
	case "relay.bind.result":
		var p struct {
			Success bool `json:"success"`
		}
		json.Unmarshal(msg.Payload, &p)
		if !p.Success {
			log.Printf("relay.bind denied by server")
		}
	case "key.rotate.result":
		var p struct {
			Success bool `json:"success"`
		}
		json.Unmarshal(msg.Payload, &p)
		if p.Success {
			log.Printf("key rotation acknowledged by server")
		}
	case "endpoint.discovered.result":
		// acknowledgement — no action needed
	default:
		log.Printf("unknown message type: %s", msg.Type)
	}
	return nil
}

func handleSync(ctx context.Context, conn *websocket.Conn, iface, msgID string, payload json.RawMessage, rm *relayManager) error {
	var p struct {
		Action string `json:"action"`
		Self   *struct {
			NodeID     int    `json:"node_id"`
			MeshIP     string `json:"mesh_ip"`
			ListenPort int    `json:"listen_port"`
		} `json:"self"`
		Peers  []peerConfig `json:"peers"`
		Peer   *peerConfig  `json:"peer"`
		Pubkey string       `json:"public_key"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("parse sync payload: %w", err)
	}

	var syncErr error
	switch p.Action {
	case "full_sync":
		// Provision interface if we have self info
		if p.Self != nil && p.Self.MeshIP != "" {
			if err := ensureInterface(iface, p.Self.ListenPort, p.Self.MeshIP); err != nil {
				log.Printf("interface provisioning: %v", err)
			}
		}
		syncErr = wgSyncFull(iface, p.Peers)
		// Update DNS entries for peers
		if err := updateHosts(p.Peers); err != nil {
			log.Printf("dns update: %v", err)
		}
		// Update relay manager's node map
		if rm != nil {
			nodeMap := make(map[string]int)
			for _, peer := range p.Peers {
				if peer.NodeID > 0 {
					nodeMap[peer.PublicKey] = peer.NodeID
				}
			}
			rm.updateNodeMap(nodeMap)
		}
	case "add_peer":
		if p.Peer != nil {
			syncErr = wgSetPeer(iface, *p.Peer)
		}
	case "remove_peer":
		if p.Pubkey != "" {
			syncErr = wgRemovePeer(iface, p.Pubkey)
		}
	default:
		log.Printf("unknown sync action: %s", p.Action)
		return nil
	}

	// Report result
	result := map[string]any{
		"type": "wg.sync.result",
		"payload": map[string]any{
			"success": syncErr == nil,
		},
	}
	if msgID != "" {
		result["id"] = msgID
	}
	if syncErr != nil {
		result["payload"].(map[string]any)["error"] = syncErr.Error()
		log.Printf("sync %s failed: %v", p.Action, syncErr)
	} else {
		log.Printf("sync %s applied", p.Action)
	}
	data, _ := json.Marshal(result)
	return conn.Write(ctx, websocket.MessageText, data)
}
