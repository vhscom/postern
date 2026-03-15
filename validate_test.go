package main

import (
	"errors"
	"testing"
)

func TestIsUniqueViolation(t *testing.T) {
	if isUniqueViolation(nil) {
		t.Error("nil error should not be a unique violation")
	}
	if isUniqueViolation(errors.New("something else")) {
		t.Error("generic error should not be a unique violation")
	}
	if !isUniqueViolation(errors.New("UNIQUE constraint failed: account.email")) {
		t.Error("UNIQUE constraint error should be detected")
	}
}

func TestValidEmail(t *testing.T) {
	tests := []struct {
		email string
		want  bool
	}{
		{"user@example.com", true},
		{"a@b.c", true},
		{"", false},
		{"@example.com", false},
		{"noat", false},
		{"no@dot", false},
	}
	for _, tt := range tests {
		if got := validEmail(tt.email); got != tt.want {
			t.Errorf("validEmail(%q) = %v, want %v", tt.email, got, tt.want)
		}
	}
}

func TestMaskEmail(t *testing.T) {
	if got := maskEmail("user@example.com"); got != "*@example.com" {
		t.Errorf("maskEmail = %q, want *@example.com", got)
	}
	if got := maskEmail("noat"); got != "" {
		t.Errorf("maskEmail(noat) = %q, want empty", got)
	}
}

func TestValidLabel(t *testing.T) {
	tests := []struct {
		label string
		want  bool
	}{
		{"gateway", true},
		{"my-node", true},
		{"Node1", true},
		{"", false},
		{"has space", false},
		{"has_underscore", false},
		{"has.dot", false},
	}
	for _, tt := range tests {
		if got := validLabel(tt.label); got != tt.want {
			t.Errorf("validLabel(%q) = %v, want %v", tt.label, got, tt.want)
		}
	}
}

func TestValidWGPubkey(t *testing.T) {
	if !validWGPubkey("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=") {
		t.Error("valid 44-char base64 key should pass")
	}
	if validWGPubkey("tooshort") {
		t.Error("short key should fail")
	}
	if validWGPubkey("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY!") {
		t.Error("key with invalid char should fail")
	}
}

func TestValidAllowedIPsCIDR(t *testing.T) {
	if !validAllowedIPs("10.0.0.1/32") {
		t.Error("valid CIDR should pass")
	}
	if validAllowedIPs("10.0.0.1") {
		t.Error("bare IP without CIDR should fail")
	}
	if validAllowedIPs("garbage") {
		t.Error("garbage should fail")
	}
}

func TestValidEndpoint(t *testing.T) {
	if !validEndpoint("1.2.3.4:51820") {
		t.Error("valid endpoint should pass")
	}
	if validEndpoint("") {
		t.Error("empty should fail")
	}
	if validEndpoint("noport") {
		t.Error("no port should fail")
	}
}
