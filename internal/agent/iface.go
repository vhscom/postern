package agent

import (
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ensureInterface creates and configures the WireGuard interface if needed.
// It sets the private key, listen port, and mesh IP address.
func ensureInterface(iface string, listenPort int, meshIP string) error {
	keyPath := filepath.Join(configDir(), "private.key")

	switch runtime.GOOS {
	case "linux":
		return ensureInterfaceLinux(iface, keyPath, listenPort, meshIP)
	case "darwin":
		return ensureInterfaceDarwin(iface, keyPath, listenPort, meshIP)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
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
		log.Printf("created interface %s", iface)
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

	log.Printf("interface %s configured: ip=%s port=%d", iface, meshIP, listenPort)
	return nil
}

func ensureInterfaceDarwin(iface, keyPath string, listenPort int, meshIP string) error {
	// On macOS, WireGuard uses utun devices via wireguard-go.
	if exec.Command("wg", "show", iface).Run() != nil {
		if _, err := exec.LookPath("wireguard-go"); err != nil {
			return fmt.Errorf("wireguard-go not found — install with: brew install wireguard-go")
		}
		out, err := exec.Command("wireguard-go", iface).CombinedOutput()
		if err != nil {
			return fmt.Errorf("wireguard-go %s: %w: %s", iface, err, out)
		}
		log.Printf("created interface %s via wireguard-go", iface)
	}

	if err := wgSetInterface(iface, keyPath, listenPort); err != nil {
		return err
	}

	// Assign mesh IP — strip /32 for ifconfig
	ip := strings.TrimSuffix(meshIP, "/32")
	out, err := exec.Command("ifconfig", iface, "inet", ip+"/32", ip).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "File exists") {
		return fmt.Errorf("ifconfig %s: %w: %s", iface, err, out)
	}

	out, err = exec.Command("ifconfig", iface, "up").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s up: %w: %s", iface, err, out)
	}

	log.Printf("interface %s configured: ip=%s port=%d", iface, meshIP, listenPort)
	return nil
}
