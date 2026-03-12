package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/term"
)

// RunLogin handles "postern login <server>".
func RunLogin() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: postern login <server-url>")
		fmt.Fprintln(os.Stderr, "Example: postern login https://postern.example.com")
		os.Exit(1)
	}

	if os.Args[1] == "--help" || os.Args[1] == "-h" {
		printLoginHelp()
		return
	}

	server := strings.TrimRight(os.Args[1], "/")

	fmt.Print("Email: ")
	var email string
	fmt.Scanln(&email)

	fmt.Print("Password: ")
	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		password = string(passBytes)
	} else {
		fmt.Scanln(&password)
	}

	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	req, err := http.NewRequest("POST", server+"/auth/login", strings.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSeeOther {
		msg := result.Error
		if msg == "" {
			msg = fmt.Sprintf("login failed (status %d)", resp.StatusCode)
		}
		fmt.Fprintf(os.Stderr, "Error: %s\n", msg)
		os.Exit(1)
	}

	// Extract cookies
	cookies := map[string]string{}
	for _, c := range resp.Cookies() {
		cookies[c.Name] = c.Value
	}
	if len(cookies) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no session cookies received")
		os.Exit(1)
	}

	sess := &storedSession{
		Server:  server,
		Cookies: cookies,
	}
	if err := saveSession(sess); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving session: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Logged in to %s\n", server)
}

func printLoginHelp() {
	printTitle("postern login", "authenticate with a postern server")
	printHeading("Usage")
	printCmd("postern login <server-url>", "")
	fmt.Println()
	printHeading("Example")
	fmt.Printf("  %s\n\n", cmdStyle.Render("postern login https://postern.example.com"))
	fmt.Printf("  Session stored in %s\n", dimStyle.Render("~/.config/postern/session.json"))
}
