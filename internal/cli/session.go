package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

type storedSession struct {
	Server  string            `json:"server"`
	Cookies map[string]string `json:"cookies"`
}

func configDir() string {
	if d := os.Getenv("POSTERN_CONFIG_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "postern")
}

func sessionPath() string {
	return filepath.Join(configDir(), "session.json")
}

func saveSession(sess *storedSession) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(sess, "", "  ")
	return os.WriteFile(sessionPath(), data, 0600)
}

func loadSession() (*storedSession, error) {
	data, err := os.ReadFile(sessionPath())
	if err != nil {
		return nil, fmt.Errorf("not logged in — run 'postern login' first")
	}
	var sess storedSession
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, fmt.Errorf("corrupt session file: %w", err)
	}
	return &sess, nil
}

func clearSession() error {
	return os.Remove(sessionPath())
}

// checkAuthExpired exits with a helpful message if the response is 401.
func checkAuthExpired(statusCode int) {
	if statusCode == http.StatusUnauthorized {
		fmt.Fprintln(os.Stderr, "Error: session expired — run 'postern login' to re-authenticate")
		os.Exit(1)
	}
}

// guardExistingConfig exits if agent config already exists and force is false.
// Returns the config dir, config path, and key path for use by the caller.
func guardExistingConfig(force bool, command string) (cfgDir, cfgPath, keyPath string) {
	cfgDir = configDir()
	cfgPath = filepath.Join(cfgDir, "config.json")
	keyPath = filepath.Join(cfgDir, "private.key")
	if !force {
		if _, err := os.Stat(cfgPath); err == nil {
			fmt.Fprintf(os.Stderr, "Error: agent config already exists at %s\n", cfgPath)
			fmt.Fprintln(os.Stderr, "This machine is already configured as a node.")
			fmt.Fprintln(os.Stderr, "Re-running would overwrite the existing private key and credentials.")
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "To replace the existing config: %s --force ...\n", command)
			os.Exit(1)
		}
	}
	return
}

// authedRequest creates an HTTP request with stored session cookies.
func authedRequest(method, path string, body io.Reader) (*http.Request, *storedSession, error) {
	sess, err := loadSession()
	if err != nil {
		return nil, nil, err
	}

	url := sess.Server + path
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for name, value := range sess.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	return req, sess, nil
}
