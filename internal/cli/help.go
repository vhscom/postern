package cli

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("5"))
	headingStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	cmdStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	flagStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	dimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
)

func printTitle(name, tagline string) {
	fmt.Printf("%s %s\n\n", titleStyle.Render(name), dimStyle.Render("— "+tagline))
}

func printHeading(s string) {
	fmt.Printf("%s\n", headingStyle.Render(s))
}

func printCmd(cmd, desc string) {
	fmt.Printf("  %s  %s\n", cmdStyle.Render(fmt.Sprintf("%-42s", cmd)), dimStyle.Render(desc))
}

func printFlag(flag, desc string) {
	fmt.Printf("  %s  %s\n", flagStyle.Render(fmt.Sprintf("%-20s", flag)), dimStyle.Render(desc))
}

func printEnv(name, desc string) {
	fmt.Printf("  %s  %s\n", flagStyle.Render(fmt.Sprintf("%-28s", name)), dimStyle.Render(desc))
}

// PrintGlobalHelp renders the top-level postern help.
func PrintGlobalHelp() {
	printTitle("postern", "WireGuard mesh control plane")
	printHeading("Usage")
	fmt.Printf("  postern <command> [flags]\n\n")
	printHeading("Commands")
	printCmd("login", "Authenticate with a postern server")
	printCmd("node add | list | remove", "Manage mesh nodes")
	printCmd("agent", "Run the WireGuard mesh agent")
	printCmd("ctl", "Launch the ops control TUI")
	printCmd("serve", "Start the postern server")
	fmt.Println()
	fmt.Printf("  Run %s for command-specific help.\n", cmdStyle.Render("postern <command> --help"))
}
