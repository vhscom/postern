package agent

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	hostsPath  = "/etc/hosts"
	hostsBegin = "# postern:begin"
	hostsEnd   = "# postern:end"
)

// updateHosts manages a postern block in /etc/hosts mapping peer labels to mesh IPs.
func updateHosts(peers []peerConfig) error {
	// Build the postern block
	var lines []string
	for _, p := range peers {
		if p.Label == "" || p.AllowedIPs == "" {
			continue
		}
		ip := strings.TrimSuffix(p.AllowedIPs, "/32")
		lines = append(lines, fmt.Sprintf("%s %s", ip, p.Label))
	}

	var b strings.Builder
	b.WriteString(hostsBegin)
	b.WriteByte('\n')
	for _, l := range lines {
		b.WriteString(l)
		b.WriteByte('\n')
	}
	b.WriteString(hostsEnd)
	block := b.String()

	// Read current hosts file
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", hostsPath, err)
	}
	content := string(data)

	// Replace or append postern block
	beginIdx := strings.Index(content, hostsBegin)
	endIdx := strings.Index(content, hostsEnd)

	var newContent string
	if beginIdx >= 0 && endIdx >= 0 {
		// Replace existing block
		newContent = content[:beginIdx] + block + content[endIdx+len(hostsEnd):]
	} else {
		// Append new block
		newContent = strings.TrimRight(content, "\n") + "\n\n" + block + "\n"
	}

	if newContent == content {
		return nil // no changes needed
	}

	if err := os.WriteFile(hostsPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("write %s: %w", hostsPath, err)
	}

	log.Printf("updated %s with %d mesh entries", hostsPath, len(lines))
	return nil
}
