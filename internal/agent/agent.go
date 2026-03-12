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

	"github.com/coder/websocket"
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
		case "--help", "-h", "help":
			fmt.Println("postern agent - WireGuard mesh agent")
			fmt.Println()
			fmt.Println("Usage:")
			fmt.Println("  postern agent              Connect to server and sync WireGuard config")
			fmt.Println("  postern agent init <server-url> <api-key> [interface]")
			fmt.Println()
			fmt.Println("Environment:")
			fmt.Println("  POSTERN_AGENT_SERVER       Server URL (overrides config file)")
			fmt.Println("  POSTERN_AGENT_TOKEN        API key (overrides config file)")
			fmt.Println("  POSTERN_AGENT_INTERFACE    WireGuard interface (default: wg0)")
			fmt.Println("  POSTERN_AGENT_CONFIG_DIR   Config directory (default: ~/.config/postern)")
			return
		}
	}

	cfg := loadConfig()
	log.Printf("postern agent: server=%s interface=%s", cfg.Server, cfg.Interface)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	connectLoop(ctx, cfg)
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
		"capabilities": []string{"wg_sync", "wg_status"},
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

	// Main loop: read server messages, report status periodically
	statusTicker := time.NewTicker(60 * time.Second)
	defer statusTicker.Stop()

	msgCh := make(chan []byte, 16)
	errCh := make(chan error, 1)

	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				errCh <- err
				return
			}
			msgCh <- data
		}
	}()

	for {
		select {
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "shutdown")
			return nil
		case err := <-errCh:
			return err
		case raw := <-msgCh:
			if err := handleMessage(ctx, conn, cfg.Interface, raw); err != nil {
				log.Printf("handle message: %v", err)
			}
		case <-statusTicker.C:
			status, err := wgShow(cfg.Interface)
			if err != nil {
				log.Printf("wg show: %v", err)
				continue
			}
			sendStatus(ctx, conn, status)
		}
	}
}

func sendStatus(ctx context.Context, conn *websocket.Conn, status *interfaceStatus) {
	msg := map[string]any{
		"type":    "wg.status",
		"payload": status,
	}
	data, _ := json.Marshal(msg)
	conn.Write(ctx, websocket.MessageText, data)
}

func handleMessage(ctx context.Context, conn *websocket.Conn, iface string, raw []byte) error {
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
		return handleSync(ctx, conn, iface, msg.ID, msg.Payload)
	default:
		log.Printf("unknown message type: %s", msg.Type)
	}
	return nil
}

func handleSync(ctx context.Context, conn *websocket.Conn, iface, msgID string, payload json.RawMessage) error {
	var p struct {
		Action string       `json:"action"`
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
		syncErr = wgSyncFull(iface, p.Peers)
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
