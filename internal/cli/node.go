package cli

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// RunNode handles "postern node <subcommand>".
func RunNode() {
	if len(os.Args) < 2 {
		printNodeUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "add":
		os.Args = os.Args[1:]
		runNodeAdd()
	case "list", "ls":
		runNodeList()
	case "remove", "rm":
		os.Args = os.Args[1:]
		runNodeRemove()
	case "--help", "-h", "help":
		printNodeUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown node command: %s\n", os.Args[1])
		printNodeUsage()
		os.Exit(1)
	}
}

func printNodeUsage() {
	printTitle("postern node", "manage mesh nodes")
	printHeading("Usage")
	printCmd("postern node add [flags]", "Add this machine to the mesh")
	printCmd("postern node list", "List all nodes in your mesh")
	printCmd("postern node remove <label>", "Remove a node from the mesh")
	fmt.Println()
	printHeading("Flags (add)")
	printFlag("--label <name>", "Node name (required)")
	printFlag("--ip <mesh-ip>", "Mesh IP, e.g. 10.0.0.1/32 (required)")
	printFlag("--endpoint <addr>", "Public endpoint, e.g. 1.2.3.4:51820")
	printFlag("--port <port>", "WireGuard listen port (default: 51820)")
	printFlag("--interface <name>", "WireGuard interface (default: wg0)")
	fmt.Println()
	printHeading("Example")
	fmt.Printf("  %s\n", cmdStyle.Render("postern node add --label gateway-nyc --ip 10.0.0.1/32 --endpoint 1.2.3.4:51820"))
	fmt.Printf("  %s\n", cmdStyle.Render("postern node add --label laptop --ip 10.0.0.2/32"))
}

func runNodeAdd() {
	var label, ip, endpoint, iface string
	port := "51820"

	for i := 1; i < len(os.Args); i++ {
		switch {
		case os.Args[i] == "--label" && i+1 < len(os.Args):
			i++
			label = os.Args[i]
		case os.Args[i] == "--ip" && i+1 < len(os.Args):
			i++
			ip = os.Args[i]
		case os.Args[i] == "--endpoint" && i+1 < len(os.Args):
			i++
			endpoint = os.Args[i]
		case os.Args[i] == "--port" && i+1 < len(os.Args):
			i++
			port = os.Args[i]
		case os.Args[i] == "--interface" && i+1 < len(os.Args):
			i++
			iface = os.Args[i]
		case os.Args[i] == "--help" || os.Args[i] == "-h":
			printNodeUsage()
			return
		}
	}

	if label == "" || ip == "" {
		fmt.Fprintln(os.Stderr, "Error: --label and --ip are required")
		fmt.Fprintln(os.Stderr, "Example: postern node add --label gateway-nyc --ip 10.0.0.1/32")
		os.Exit(1)
	}
	if iface == "" {
		iface = "wg0"
	}

	// Generate WireGuard keypair
	privKey, pubKey, err := generateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	// Build request
	reqBody := map[string]any{
		"label":          label,
		"wg_pubkey":      pubKey,
		"allowed_ips":    ip,
		"wg_listen_port": json.Number(port),
		"interface_name": iface,
	}
	if endpoint != "" {
		reqBody["wg_endpoint"] = endpoint
	}
	data, _ := json.Marshal(reqBody)

	req, sess, err := authedRequest("POST", "/account/nodes", strings.NewReader(string(data)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(respBody, &result)

	if resp.StatusCode != http.StatusCreated {
		msg := "registration failed"
		if e, ok := result["error"].(string); ok {
			msg = e
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		os.Exit(1)
	}

	apiKey, _ := result["api_key"].(string)

	// Write agent config
	agentCfg := map[string]string{
		"server":    sess.Server,
		"token":     apiKey,
		"interface": iface,
	}
	cfgData, _ := json.MarshalIndent(agentCfg, "", "  ")
	cfgDir := configDir()
	os.MkdirAll(cfgDir, 0700)
	cfgPath := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfgPath, cfgData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write agent config: %v\n", err)
	}

	// Save private key separately
	keyPath := filepath.Join(cfgDir, "private.key")
	if err := os.WriteFile(keyPath, []byte(privKey+"\n"), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write private key: %v\n", err)
	}

	fmt.Printf("Node '%s' added to mesh\n", label)
	fmt.Printf("  Mesh IP:     %s\n", ip)
	fmt.Printf("  Public key:  %s\n", pubKey)
	fmt.Printf("  Interface:   %s\n", iface)
	fmt.Printf("  Config:      %s\n", cfgPath)
	fmt.Printf("  Private key: %s\n", keyPath)
	fmt.Println()
	fmt.Println("Start the agent:")
	fmt.Printf("  postern agent\n")
}

func runNodeList() {
	req, _, err := authedRequest("GET", "/account/nodes", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var result map[string]any
		json.Unmarshal(body, &result)
		msg := "request failed"
		if e, ok := result["error"].(string); ok {
			msg = e
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		os.Exit(1)
	}

	var result struct {
		Nodes []struct {
			Label      string  `json:"label"`
			WGPubkey   string  `json:"wg_pubkey"`
			WGEndpoint *string `json:"wg_endpoint"`
			AllowedIPs string  `json:"allowed_ips"`
			LastSeenAt *string `json:"last_seen_at"`
		} `json:"nodes"`
	}
	json.Unmarshal(body, &result)

	if len(result.Nodes) == 0 {
		fmt.Println("No nodes in mesh.")
		fmt.Println("Add one: postern node add --label <name> --ip <mesh-ip>")
		return
	}

	fmt.Printf("Mesh (%d nodes)\n\n", len(result.Nodes))
	fmt.Printf("  %-16s %-18s %-24s %-10s\n", "LABEL", "MESH IP", "ENDPOINT", "STATUS")
	fmt.Printf("  %-16s %-18s %-24s %-10s\n",
		strings.Repeat("-", 16), strings.Repeat("-", 18),
		strings.Repeat("-", 24), strings.Repeat("-", 10))

	for _, n := range result.Nodes {
		endpoint := "-"
		if n.WGEndpoint != nil {
			endpoint = *n.WGEndpoint
		}
		status := "offline"
		if n.LastSeenAt != nil {
			status = "seen"
		}
		fmt.Printf("  %-16s %-18s %-24s %-10s\n",
			n.Label, n.AllowedIPs, endpoint, status)
	}
}

func runNodeRemove() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: postern node remove <label>")
		os.Exit(1)
	}
	label := os.Args[1]

	req, _, err := authedRequest("DELETE", "/account/nodes/"+label, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var result map[string]any
		json.Unmarshal(body, &result)
		msg := "removal failed"
		if e, ok := result["error"].(string); ok {
			msg = e
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		os.Exit(1)
	}

	fmt.Printf("Node '%s' removed from mesh.\n", label)
}

func generateKeypair() (privateKey, publicKey string, err error) {
	var private [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return "", "", err
	}

	// Clamp private key per WireGuard spec
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	pub, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}

	return base64.StdEncoding.EncodeToString(private[:]),
		base64.StdEncoding.EncodeToString(pub), nil
}
