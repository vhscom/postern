package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"postern/internal/agent"
	"postern/internal/wgkey"
)

// RunJoin handles "postern join <server-url> <token> [--label name]".
func RunJoin() {
	if len(os.Args) < 3 {
		printJoinUsage()
		os.Exit(1)
	}
	if os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "help" {
		printJoinUsage()
		return
	}

	serverURL := os.Args[1]
	token := os.Args[2]
	var label, iface string
	var force bool

	for i := 3; i < len(os.Args); i++ {
		switch {
		case (os.Args[i] == "--label" || os.Args[i] == "-l") && i+1 < len(os.Args):
			i++
			label = os.Args[i]
		case os.Args[i] == "--interface" && i+1 < len(os.Args):
			i++
			iface = os.Args[i]
		case os.Args[i] == "--force" || os.Args[i] == "-f":
			force = true
		case os.Args[i] == "--no-agent":
			// handled by main
		case os.Args[i] == "--help" || os.Args[i] == "-h":
			printJoinUsage()
			return
		}
	}

	if iface == "" {
		iface = agent.DefaultInterface()
	}

	// Auto-detect label from hostname if not provided
	if label == "" {
		hostname, _ := os.Hostname()
		label = sanitizeLabel(hostname)
	}
	if label == "" {
		fmt.Fprintln(os.Stderr, "Error: could not determine label — use --label <name>")
		os.Exit(1)
	}

	// Guard against overwriting existing agent config
	cfgDir := configDir()
	cfgPath := filepath.Join(cfgDir, "config.json")
	keyPath := filepath.Join(cfgDir, "private.key")
	if !force {
		if _, err := os.Stat(cfgPath); err == nil {
			fmt.Fprintf(os.Stderr, "Error: agent config already exists at %s\n", cfgPath)
			fmt.Fprintln(os.Stderr, "This machine is already configured as a node. Joining again")
			fmt.Fprintln(os.Stderr, "would overwrite the existing private key and credentials.")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(os.Stderr, "To replace the existing config: postern join --force ...")
			os.Exit(1)
		}
	}

	// Generate WireGuard keypair
	privKey, pubKey, err := wgkey.GenerateKeypair()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating keypair: %v\n", err)
		os.Exit(1)
	}

	// Call POST /join
	reqBody := map[string]string{
		"token":     token,
		"label":     label,
		"wg_pubkey": pubKey,
	}
	data, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", serverURL+"/join", strings.NewReader(string(data)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)

	if resp.StatusCode != http.StatusCreated {
		msg := fmt.Sprintf("join failed (status %d)", resp.StatusCode)
		if e, ok := result["error"].(string); ok {
			msg = e
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		os.Exit(1)
	}

	apiKey, _ := result["api_key"].(string)
	meshIP, _ := result["mesh_ip"].(string)

	// Use ops URL if server reports a split ops surface
	agentServer := serverURL
	if opsURL, ok := result["ops_url"].(string); ok && opsURL != "" {
		agentServer = opsURL
	}

	// Write agent config
	os.MkdirAll(cfgDir, 0700)
	agentCfg := map[string]string{
		"server":    agentServer,
		"token":     apiKey,
		"interface": iface,
	}
	cfgData, _ := json.MarshalIndent(agentCfg, "", "  ")
	if err := os.WriteFile(cfgPath, cfgData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write agent config: %v\n", err)
	}

	// Save private key
	if err := os.WriteFile(keyPath, []byte(privKey+"\n"), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write private key: %v\n", err)
	}

	fmt.Printf("Joined mesh as '%s'\n", label)
	fmt.Printf("  Mesh IP:     %s\n", meshIP)
	fmt.Printf("  Public key:  %s\n", pubKey)
	fmt.Printf("  Config:      %s\n", cfgPath)
}

func printJoinUsage() {
	printTitle("postern join", "join a mesh from an invite")
	printHeading("Usage")
	printCmd("postern join <server-url> <token> [--label name]", "Join using an invite token")
	fmt.Println()
	printHeading("Options")
	printFlag("--label <name>", "Node name (default: hostname)")
	printFlag("--interface <name>", "WireGuard interface (default: utun3/wg0)")
	printFlag("--no-agent", "Don't start the agent after joining")
	printFlag("--force", "Overwrite existing agent config")
	fmt.Println()
	printHeading("Example")
	fmt.Printf("  %s\n", cmdStyle.Render("postern join https://postern.example.com abc123def"))
}

// sanitizeLabel converts a hostname into a valid node label.
func sanitizeLabel(hostname string) string {
	hostname = strings.ToLower(hostname)
	// Strip common suffixes
	hostname = strings.TrimSuffix(hostname, ".local")
	hostname = strings.TrimSuffix(hostname, ".lan")

	// Keep only valid label characters
	var b strings.Builder
	for _, c := range hostname {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else if c == '.' || c == '_' || c == ' ' {
			b.WriteByte('-')
		}
	}

	label := strings.Trim(b.String(), "-")
	if len(label) > 32 {
		label = strings.TrimRight(label[:32], "-")
	}
	return label
}
