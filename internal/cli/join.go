package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
	var label string

	for i := 3; i < len(os.Args); i++ {
		switch {
		case (os.Args[i] == "--label" || os.Args[i] == "-l") && i+1 < len(os.Args):
			i++
			label = os.Args[i]
		case os.Args[i] == "--no-agent":
			// handled by main
		case os.Args[i] == "--help" || os.Args[i] == "-h":
			printJoinUsage()
			return
		}
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

	resp, err := http.Post(serverURL+"/join", "application/json", strings.NewReader(string(data)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)

	if resp.StatusCode != http.StatusCreated {
		msg := "join failed"
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
	cfgDir := configDir()
	os.MkdirAll(cfgDir, 0700)

	agentCfg := map[string]string{
		"server":    agentServer,
		"token":     apiKey,
		"interface": "wg0",
	}
	cfgData, _ := json.MarshalIndent(agentCfg, "", "  ")
	cfgPath := filepath.Join(cfgDir, "config.json")
	if err := os.WriteFile(cfgPath, cfgData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not write agent config: %v\n", err)
	}

	// Save private key
	keyPath := filepath.Join(cfgDir, "private.key")
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
	printFlag("--no-agent", "Don't start the agent after joining")
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
