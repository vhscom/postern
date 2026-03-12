package cli

import "testing"

func TestSanitizeLabel(t *testing.T) {
	tests := []struct {
		hostname string
		want     string
	}{
		{"macbook-pro", "macbook-pro"},
		{"MacBook-Pro.local", "macbook-pro"},
		{"server.lan", "server"},
		{"my_workstation", "my-workstation"},
		{"GATEWAY-NYC", "gateway-nyc"},
		{"node with spaces", "node-with-spaces"},
		{"a.b.c.d", "a-b-c-d"},
		{"", ""},
		{"---leading---", "leading"},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, // 36 -> truncated to 32
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},     // 31 a's + dot + b -> truncate leaves trailing hyphen, stripped
	}
	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			got := sanitizeLabel(tt.hostname)
			if got != tt.want {
				t.Errorf("sanitizeLabel(%q) = %q, want %q", tt.hostname, got, tt.want)
			}
		})
	}
}
