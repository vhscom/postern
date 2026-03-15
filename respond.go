package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// --- Content negotiation ---

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json")
}

func respondSuccess(w http.ResponseWriter, r *http.Request, status int, msg, redirect string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{"success": true, "message": msg})
	} else {
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

func respondError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	if wantsJSON(r) {
		jsonError(w, status, code, msg)
	} else {
		http.Redirect(w, r, "/#error", http.StatusFound)
	}
}

func jsonError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg, "code": code})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonCreated(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(v)
}

// --- Request parsing ---

func parseCredentials(r *http.Request) (email, password string) {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		return strings.ToLower(strings.TrimSpace(body.Email)), body.Password
	}
	r.ParseForm()
	return strings.ToLower(strings.TrimSpace(r.FormValue("email"))), r.FormValue("password")
}

func parsePasswordChange(r *http.Request) (current, next string) {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var body struct {
			CurrentPassword string `json:"currentPassword"`
			NewPassword     string `json:"newPassword"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		return body.CurrentPassword, body.NewPassword
	}
	r.ParseForm()
	return r.FormValue("currentPassword"), r.FormValue("newPassword")
}

// --- Validation ---

func validEmail(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}
	parts := strings.SplitN(email, "@", 2)
	return len(parts) == 2 && len(parts[0]) > 0 && strings.Contains(parts[1], ".")
}

// maskEmail returns "*@domain" for event logging (never log full addresses).
func maskEmail(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		return "*@" + email[i+1:]
	}
	return ""
}

func validPassword(password string) bool {
	n := utf8.RuneCountInString(normalizePassword(password))
	return n >= 8 && n <= 64
}

func validLabel(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
			return false
		}
	}
	return true
}

func validEndpoint(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	i := strings.LastIndex(s, ":")
	return i > 0 && i < len(s)-1
}

func validAllowedIPs(s string) bool {
	_, _, err := net.ParseCIDR(s)
	return err == nil
}

func validWGPubkey(s string) bool {
	// WireGuard public keys: 32 bytes base64-encoded = 44 chars ending with =
	if len(s) != 44 || s[43] != '=' {
		return false
	}
	for _, c := range s[:43] {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/') {
			return false
		}
	}
	return true
}

// --- Cookie helpers ---

func setAuthCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func deleteAuthCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func setTokenCookies(w http.ResponseWriter, uid int, sid string) error {
	access, err := signToken(uid, sid, "access", cfg.AccessSecret, accessExpiry)
	if err != nil {
		return err
	}
	refresh, err := signToken(uid, sid, "refresh", cfg.RefreshSecret, refreshExpiry)
	if err != nil {
		return err
	}
	setAuthCookie(w, "access_token", access, accessExpiry)
	setAuthCookie(w, "refresh_token", refresh, refreshExpiry)
	return nil
}

func clearTokenCookies(w http.ResponseWriter) {
	deleteAuthCookie(w, "access_token")
	deleteAuthCookie(w, "refresh_token")
}

// --- IP helpers ---

// connIP returns the IP from the TCP connection (RemoteAddr), ignoring
// forwarded headers. Use for security-critical checks like IP allowlists.
func connIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if i := strings.Index(fwd, ","); i > 0 {
			return strings.TrimSpace(fwd[:i])
		}
		return strings.TrimSpace(fwd)
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

func isNavigation(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Dest") == "document" ||
		r.Header.Get("Sec-Fetch-Mode") == "navigate"
}

// --- Error logging ---

func logError(op string, err error) {
	if err != nil {
		log.Printf("[error] %s: %v", op, err)
	}
}
