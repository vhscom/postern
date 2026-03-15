package agent

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
)

// agentStatus tracks the current agent state and renders it as a compact
// status block. All methods are safe for concurrent use.
type agentStatus struct {
	mu sync.Mutex

	server    string
	iface     string
	state     string // connecting, connected, syncing, ready, reconnecting
	meshIP    string
	endpoint  string
	peers     int
	lastError string
	events    []string // rolling log of recent events
	hinted    bool     // true after the one-time next-steps hint has been shown
}

var (
	labelStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	valueStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
	okStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	warnStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	errStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	headerStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
)

const maxEvents = 8

func newAgentStatus(server, iface string) *agentStatus {
	return &agentStatus{
		server: server,
		iface:  iface,
		state:  "connecting",
	}
}

func (s *agentStatus) setConnected() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = "connected"
	s.lastError = ""
	s.addEvent("connected")
}

func (s *agentStatus) setSyncing() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = "syncing"
}

func (s *agentStatus) setReady(peers int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = "ready"
	s.peers = peers
}

func (s *agentStatus) setReconnecting(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = "reconnecting"
	s.lastError = reason
	s.addEvent("disconnected: " + reason)
}

func (s *agentStatus) setMeshIP(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.meshIP = ip
}

func (s *agentStatus) setEndpoint(ep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpoint = ep
	s.addEvent("endpoint " + ep)
}

func (s *agentStatus) setPeers(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers = n
}

func (s *agentStatus) logSync(action string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.addEvent("sync " + action + " failed: " + err.Error())
	} else {
		s.addEvent("sync " + action)
	}
}

func (s *agentStatus) logEvent(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addEvent(msg)
}

func (s *agentStatus) logError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastError = msg
	s.addEvent(msg)
}

// addEvent appends to the rolling event log. Caller must hold mu.
func (s *agentStatus) addEvent(msg string) {
	s.events = append(s.events, msg)
	if len(s.events) > maxEvents {
		s.events = s.events[len(s.events)-maxEvents:]
	}
}

// render prints the current status block to stderr.
func (s *agentStatus) render() {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder

	b.WriteString(headerStyle.Render("postern agent"))
	b.WriteString(labelStyle.Render(" · "))
	b.WriteString(valueStyle.Render(s.iface))
	b.WriteByte('\n')

	row := func(label, value string, style lipgloss.Style) {
		b.WriteString(fmt.Sprintf("  %s %s\n",
			labelStyle.Render(fmt.Sprintf("%-10s", label)),
			style.Render(value)))
	}

	row("server", s.server, valueStyle)

	if s.meshIP != "" {
		row("mesh ip", s.meshIP, valueStyle)
	}

	switch s.state {
	case "connecting":
		row("status", "connecting...", warnStyle)
	case "connected":
		row("status", "connected", okStyle)
	case "syncing":
		row("status", "syncing...", warnStyle)
	case "ready":
		row("status", "ready", okStyle)
	case "reconnecting":
		row("status", "reconnecting...", warnStyle)
	}

	if s.peers > 0 {
		row("peers", fmt.Sprintf("%d synced", s.peers), valueStyle)
	}

	if s.endpoint != "" {
		row("endpoint", s.endpoint, valueStyle)
	}

	if s.lastError != "" {
		row("error", s.lastError, errStyle)
	}

	if len(s.events) > 0 {
		b.WriteByte('\n')
		for _, e := range s.events {
			style := dimStyle
			if strings.Contains(e, "failed") || strings.Contains(e, "error") {
				style = errStyle
			}
			b.WriteString(fmt.Sprintf("  %s %s\n",
				dimStyle.Render("·"),
				style.Render(e)))
		}
	}

	if s.state == "ready" && !s.hinted {
		s.hinted = true
		b.WriteByte('\n')
		b.WriteString(dimStyle.Render("  This process must stay running. To run in the background:"))
		b.WriteByte('\n')
		b.WriteString(fmt.Sprintf("    %s\n", okStyle.Render("postern agent install")))
	}

	fmt.Fprint(os.Stderr, b.String())
}
