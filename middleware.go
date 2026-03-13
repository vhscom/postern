package main

import (
	"bufio"
	"context"
	"crypto/subtle"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Context keys ---

type ctxKey int

const (
	ctxClaims ctxKey = iota
	ctxAgentPrincipal
)

func getClaims(r *http.Request) *TokenClaims {
	v, _ := r.Context().Value(ctxClaims).(*TokenClaims)
	return v
}

type AgentPrincipal struct {
	ID         int
	Name       string
	TrustLevel string
	UserID     *int // set for node-bound agents, nil for ops agents
}

func getAgent(r *http.Request) *AgentPrincipal {
	v, _ := r.Context().Value(ctxAgentPrincipal).(*AgentPrincipal)
	return v
}

// --- Auth middleware (JWT dual-token with auto-refresh) ---

func requireAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := tryAccessToken(r)
		if err != nil {
			claims, err = tryRefreshAndRotate(w, r)
		}
		if err != nil || claims == nil {
			jsonError(w, http.StatusUnauthorized, "TOKEN_EXPIRED", "Authentication required")
			return
		}
		// Validate session still exists
		sess, _ := getSession(claims.SID)
		if sess == nil {
			jsonError(w, http.StatusForbidden, "SESSION_REVOKED", "Session expired")
			return
		}
		ctx := context.WithValue(r.Context(), ctxClaims, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tryAccessToken(r *http.Request) (*TokenClaims, error) {
	c, err := r.Cookie("access_token")
	if err != nil {
		return nil, err
	}
	return verifyToken(c.Value, cfg.AccessSecret, "access")
}

func tryRefreshAndRotate(w http.ResponseWriter, r *http.Request) (*TokenClaims, error) {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		return nil, err
	}
	refresh, err := verifyToken(c.Value, cfg.RefreshSecret, "refresh")
	if err != nil {
		return nil, err
	}
	// Validate session
	sess, _ := getSession(refresh.SID)
	if sess == nil {
		return nil, errSessionRevoked
	}
	// Generate new access token
	access, err := signToken(refresh.UID, refresh.SID, "access", cfg.AccessSecret, accessExpiry)
	if err != nil {
		return nil, err
	}
	setAuthCookie(w, "access_token", access, accessExpiry)
	return verifyToken(access, cfg.AccessSecret, "access")
}

var errSessionRevoked = &authError{"SESSION_REVOKED"}

type authError struct{ code string }

func (e *authError) Error() string { return e.code }

// --- Agent key middleware ---

func requireAgentKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, http.StatusUnauthorized, "MISSING_KEY", "Bearer token required")
			return
		}
		raw := auth[7:]
		keyHash := hashAPIKey(raw)

		var agent AgentPrincipal
		err := store.QueryRow(
			"SELECT id, name, trust_level, user_id FROM agent_credential WHERE key_hash = ? AND revoked_at IS NULL",
			keyHash,
		).Scan(&agent.ID, &agent.Name, &agent.TrustLevel, &agent.UserID)
		if err != nil {
			emitEvent("agent.auth_failure", clientIP(r), 0, r.UserAgent(), 401, nil)
			jsonError(w, http.StatusUnauthorized, "INVALID_KEY", "Invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), ctxAgentPrincipal, &agent)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requireOpsAgent restricts access to system-level agent credentials.
// Node-bound credentials (user_id set) are scoped to a single user's mesh
// and must not reach the cross-tenant ops surface.
func requireOpsAgent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := getAgent(r)
		if agent == nil || agent.UserID != nil {
			jsonError(w, http.StatusForbidden, "INSUFFICIENT_TRUST", "Ops access requires a system agent credential")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireWriteTrust(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent := getAgent(r)
		if agent == nil || agent.TrustLevel != "write" {
			jsonError(w, http.StatusForbidden, "INSUFFICIENT_TRUST", "Write trust required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Provisioning secret middleware ---

func requireProvisioningSecret(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.AgentSecret == "" {
			http.NotFound(w, r)
			return
		}
		got := r.Header.Get("X-Provisioning-Secret")
		if subtle.ConstantTimeCompare([]byte(cfg.AgentSecret), []byte(got)) != 1 {
			jsonError(w, http.StatusUnauthorized, "INVALID_SECRET", "Invalid provisioning secret")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- Access logging ---

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Microsecond))
	})
}

// --- Security headers (OWASP) ---

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Permitted-Cross-Domain-Policies", "none")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'; worker-src blob:; upgrade-insecure-requests")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Embedder-Policy", "require-corp")
		h.Set("Permissions-Policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), cross-origin-isolated=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), sync-xhr=(self), usb=(), web-share=(), xr-spatial-tracking=()")
		h.Set("Cache-Control", "no-store, max-age=0")
		h.Del("Server")
		h.Del("X-Powered-By")
		next.ServeHTTP(w, r)
	})
}

// --- In-memory fixed-window rate limiter ---

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	count   int
	resetAt time.Time
}

var limiter = &rateLimiter{windows: make(map[string]*window)}

type rateConfig struct {
	Window time.Duration
	Max    int
	Prefix string
	// KeyFunc extracts the rate limit key. Defaults to client IP.
	KeyFunc func(*http.Request) string
}

func rateLimit(rc rateConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rc.Prefix + ":"
			if rc.KeyFunc != nil {
				key += rc.KeyFunc(r)
			} else {
				key += clientIP(r)
			}

			limiter.mu.Lock()
			win, ok := limiter.windows[key]
			now := time.Now()
			if !ok || now.After(win.resetAt) {
				win = &window{count: 0, resetAt: now.Add(rc.Window)}
				limiter.windows[key] = win
			}
			win.count++
			exceeded := win.count > rc.Max
			limiter.mu.Unlock()

			if exceeded {
				emitEvent("rate_limit.reject", clientIP(r), 0, r.UserAgent(), 429, map[string]any{"prefix": rc.Prefix})
				w.Header().Set("Retry-After", "60")
				jsonError(w, http.StatusTooManyRequests, "RATE_LIMIT", "Too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Periodic cleanup of expired windows
func init() {
	go func() {
		for range time.Tick(5 * time.Minute) {
			limiter.mu.Lock()
			now := time.Now()
			for k, w := range limiter.windows {
				if now.After(w.resetAt) {
					delete(limiter.windows, k)
				}
			}
			limiter.mu.Unlock()
		}
	}()
}

// --- Control guard (uid=1 + IP allowlist) ---

func controlGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := getClaims(r)
		if claims == nil || claims.UID != 1 {
			if isNavigation(r) {
				http.Redirect(w, r, "/?return="+r.URL.Path, http.StatusFound)
				return
			}
			http.NotFound(w, r)
			return
		}
		if len(cfg.AllowedIPs) > 0 {
			if !cfg.AllowedIPs[clientIP(r)] {
				http.NotFound(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// userKey extracts a rate-limit key from authenticated requests.
func userKey(r *http.Request) string {
	if claims := getClaims(r); claims != nil {
		return strconv.Itoa(claims.UID)
	}
	return clientIP(r)
}

// --- Cloaking middleware for /ops ---

func cloakOps(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.AgentSecret == "" {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
