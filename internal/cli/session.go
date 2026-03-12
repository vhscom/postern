package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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

// authedRequest creates an HTTP request with stored session cookies.
func authedRequest(method, path string, body *strings.Reader) (*http.Request, *storedSession, error) {
	sess, err := loadSession()
	if err != nil {
		return nil, nil, err
	}

	url := sess.Server + path
	var req *http.Request
	if body != nil {
		req, err = http.NewRequest(method, url, body)
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
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
