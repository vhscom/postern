package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultInterface returns the platform-appropriate default WireGuard interface name.
func DefaultInterface() string {
	if runtime.GOOS == "darwin" {
		return "utun3"
	}
	return "wg0"
}

// ensureInterface creates and configures the WireGuard interface if needed.
// It returns the actual interface name used (may differ on macOS if the
// requested utun device was unavailable).
func ensureInterface(iface string, listenPort int, meshIP string) (string, error) {
	keyPath := filepath.Join(configDir(), "private.key")

	switch runtime.GOOS {
	case "linux":
		return iface, ensureInterfaceLinux(iface, keyPath, listenPort, meshIP)
	case "darwin":
		return ensureInterfaceDarwin(iface, keyPath, listenPort, meshIP)
	default:
		return "", fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// wgSetInterface applies private key and listen port to an existing interface.
func wgSetInterface(iface, keyPath string, listenPort int) error {
	out, err := exec.Command("wg", "set", iface,
		"private-key", keyPath,
		"listen-port", fmt.Sprint(listenPort),
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg set %s: %w: %s", iface, err, out)
	}
	return nil
}

func ensureInterfaceLinux(iface, keyPath string, listenPort int, meshIP string) error {
	// Create interface if it doesn't exist
	if exec.Command("ip", "link", "show", iface).Run() != nil {
		out, err := exec.Command("ip", "link", "add", iface, "type", "wireguard").CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip link add %s: %w: %s", iface, err, out)
		}
		// logged by status block
	}

	if err := wgSetInterface(iface, keyPath, listenPort); err != nil {
		return err
	}

	// Assign mesh IP (flush existing first to avoid conflicts)
	exec.Command("ip", "addr", "flush", "dev", iface).Run()
	out, err := exec.Command("ip", "addr", "add", meshIP, "dev", iface).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "File exists") {
		return fmt.Errorf("ip addr add %s: %w: %s", meshIP, err, out)
	}

	// Bring interface up
	out, err = exec.Command("ip", "link", "set", iface, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set %s up: %w: %s", iface, err, out)
	}

	// logged by status block
	return nil
}

// ensureInterfaceDarwin returns the actual interface name used.
func ensureInterfaceDarwin(iface, keyPath string, listenPort int, meshIP string) (string, error) {
	// On macOS, WireGuard uses utun devices via wireguard-go.
	if exec.Command("wg", "show", iface).Run() != nil {
		if _, err := exec.LookPath("wireguard-go"); err != nil {
			return "", fmt.Errorf("wireguard-go not found — install with: brew install wireguard-go")
		}

		// Try requested interface first, then scan for an available one
		candidates := []string{iface}
		if strings.HasPrefix(iface, "utun") {
			for i := 3; i <= 15; i++ {
				name := fmt.Sprintf("utun%d", i)
				if name != iface {
					candidates = append(candidates, name)
				}
			}
		}

		created := false
		for _, name := range candidates {
			// Clean up stale UAPI socket from previous runs
			os.Remove(fmt.Sprintf("/var/run/wireguard/%s.sock", name))

			out, err := exec.Command("wireguard-go", name).CombinedOutput()
			if err == nil {
				iface = name
				created = true
				// interface name logged by status block
				break
			}
			outStr := string(out)
			if strings.Contains(outStr, "not permitted") {
				return "", fmt.Errorf("wireguard-go %s: %w: %s", name, err, outStr)
			}
			// Interface busy — try next
		}
		if !created {
			return "", fmt.Errorf("no available utun device (utun3-utun15 all in use)")
		}
	}

	// wireguard-go needs a moment to initialize its UAPI socket
	var setErr error
	for tries := 0; tries < 5; tries++ {
		if tries > 0 {
			time.Sleep(200 * time.Millisecond)
		}
		setErr = wgSetInterface(iface, keyPath, listenPort)
		if setErr == nil {
			break
		}
	}
	if setErr != nil {
		// Clean up the interface we just created
		exec.Command("rm", "-f", fmt.Sprintf("/var/run/wireguard/%s.sock", iface)).Run()
		return "", setErr
	}

	// Assign mesh IP — strip /32 for ifconfig
	ip := strings.TrimSuffix(meshIP, "/32")
	out, err := exec.Command("ifconfig", iface, "inet", ip+"/32", ip).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "File exists") {
		return "", fmt.Errorf("ifconfig %s: %w: %s", iface, err, out)
	}

	out, err = exec.Command("ifconfig", iface, "up").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ifconfig %s up: %w: %s", iface, err, out)
	}

	// logged by status block
	return iface, nil
}
