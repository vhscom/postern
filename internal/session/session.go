package session

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Credentials stores connection details for posternctl.
type Credentials struct {
	Addr               string `json:"addr"`
	APIKey             string `json:"api_key"`
	ProvisioningSecret string `json:"provisioning_secret,omitempty"`
}

func configDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "posternctl")
}

func configPath() string {
	return filepath.Join(configDir(), "credentials.json")
}

// Load reads stored credentials from ~/.config/posternctl/credentials.json.
func Load() (*Credentials, error) {
	data, err := os.ReadFile(configPath())
	if err != nil {
		return nil, err
	}
	var creds Credentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

// Save writes credentials to ~/.config/posternctl/credentials.json.
func Save(creds *Credentials) error {
	if err := os.MkdirAll(configDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath(), data, 0600)
}

// InputBuffer manages text input state for the TUI.
type InputBuffer struct {
	Value string
}

// Append adds runes to the buffer.
func (b *InputBuffer) Append(runes []rune) {
	if len(runes) > 0 {
		b.Value += string(runes)
	}
}

// Backspace removes the last character.
func (b *InputBuffer) Backspace() {
	if len(b.Value) > 0 {
		b.Value = b.Value[:len(b.Value)-1]
	}
}

// Clear resets the buffer.
func (b *InputBuffer) Clear() {
	b.Value = ""
}
