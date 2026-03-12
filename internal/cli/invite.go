package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// RunInvite handles "postern invite" — creates an invite token for adding nodes.
func RunInvite() {
	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h" || os.Args[1] == "help") {
		printInviteUsage()
		return
	}

	data, _ := json.Marshal(map[string]any{})
	req, _, err := authedRequest("POST", "/account/nodes/invite", strings.NewReader(string(data)))
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
	var result map[string]any
	json.Unmarshal(body, &result)

	if resp.StatusCode != http.StatusCreated {
		msg := "invite failed"
		if e, ok := result["error"].(string); ok {
			msg = e
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		os.Exit(1)
	}

	joinCmd, _ := result["join_command"].(string)
	expiresIn, _ := result["expires_in"].(string)

	fmt.Println("Invite created. Run this on the new machine:")
	fmt.Println()
	fmt.Printf("  %s\n", cmdStyle.Render(joinCmd))
	fmt.Println()
	fmt.Printf("Token expires in %s.\n", expiresIn)
}

func printInviteUsage() {
	printTitle("postern invite", "create a join token")
	printHeading("Usage")
	printCmd("postern invite", "Create an invite token for adding nodes")
	fmt.Println()
	printHeading("Description")
	fmt.Println("  Creates a one-time token that lets another machine join your mesh")
	fmt.Println("  without needing to log in. The token expires in 24 hours.")
}
