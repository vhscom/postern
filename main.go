package main

import (
	"context"
	"embed"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

//go:embed public
var publicFS embed.FS

// Config holds all runtime settings loaded from environment variables.
type Config struct {
	Addr             string
	DBPath           string
	AccessSecret     string
	RefreshSecret    string
	AgentSecret      string // optional: enables /ops surface
	GatewayURL       string // optional: enables control proxy
	GatewayToken     string // optional: enables WS proxy token injection
	AllowedIPs       map[string]bool
	CookieSecure     bool
	WSAllowedOrigins string
	Environment      string
}

var cfg *Config

func main() {
	cfg = loadConfig()
	initDB(cfg.DBPath)

	mux := http.NewServeMux()

	// --- Static files (embedded) ---
	indexHTML, _ := publicFS.ReadFile("public/index.html")
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})

	// --- Public ---
	mux.HandleFunc("GET /health", handleHealth)

	// --- Auth lifecycle (rate-limited) ---
	loginRL := rateLimit(rateConfig{Window: 5 * time.Minute, Max: 5, Prefix: "rl:login"})
	registerRL := rateLimit(rateConfig{Window: 5 * time.Minute, Max: 5, Prefix: "rl:register"})
	logoutRL := rateLimit(rateConfig{Window: 5 * time.Minute, Max: 5, Prefix: "rl:logout", KeyFunc: userKey})
	passwordRL := rateLimit(rateConfig{Window: time.Hour, Max: 3, Prefix: "rl:password", KeyFunc: userKey})

	mux.Handle("POST /auth/register", registerRL(http.HandlerFunc(handleRegister)))
	mux.Handle("POST /auth/login", loginRL(http.HandlerFunc(handleLogin)))
	mux.Handle("POST /auth/logout", logoutRL(requireAuthMiddleware(http.HandlerFunc(handleLogout))))

	// --- Account management (authenticated) ---
	mux.Handle("POST /account/password", passwordRL(requireAuthMiddleware(http.HandlerFunc(handlePasswordChange))))
	mux.Handle("GET /account/me", requireAuthMiddleware(http.HandlerFunc(handleMe)))

	// --- Ops surface (cloaked when AGENT_PROVISIONING_SECRET absent) ---
	ops := http.NewServeMux()

	// Agent management (provisioning secret)
	ops.Handle("POST /ops/agents", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentCreate)))
	ops.Handle("DELETE /ops/agents/{name}", requireProvisioningSecret(http.HandlerFunc(handleOpsAgentRevoke)))

	// Agent-key protected routes
	ops.Handle("GET /ops/agents", requireAgentKey(http.HandlerFunc(handleOpsAgentList)))
	ops.Handle("GET /ops/sessions", requireAgentKey(http.HandlerFunc(handleOpsSessions)))
	ops.Handle("POST /ops/sessions/revoke", requireAgentKey(requireWriteTrust(http.HandlerFunc(handleOpsSessionRevoke))))
	ops.Handle("GET /ops/events", requireAgentKey(http.HandlerFunc(handleOpsEvents)))
	ops.Handle("GET /ops/events/stats", requireAgentKey(http.HandlerFunc(handleOpsEventStats)))

	// WebSocket multiplexer: Bearer → agent WS, Cookie → bridge proxy
	ops.HandleFunc("GET /ops/ws", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			requireAgentKey(http.HandlerFunc(handleOpsWS)).ServeHTTP(w, r)
			return
		}
		// Cookie path → control bridge
		if cfg.GatewayURL == "" || cfg.GatewayToken == "" {
			http.NotFound(w, r)
			return
		}
		requireAuthMiddleware(controlGuard(newBridge())).ServeHTTP(w, r)
	})

	// Control proxy routes
	ops.Handle("/ops/control", cloakOps(requireAuthMiddleware(controlGuard(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				newBridge().ServeHTTP(w, r)
				return
			}
			u := r.URL
			u.Path += "/"
			http.Redirect(w, r, u.Path+u.RawQuery, http.StatusPermanentRedirect)
		}),
	))))
	ops.Handle("/ops/control/", cloakOps(requireAuthMiddleware(controlGuard(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				newBridge().ServeHTTP(w, r)
				return
			}
			newProxy().ServeHTTP(w, r)
		}),
	))))

	// Mount ops under cloak
	mux.Handle("/ops/", cloakOps(ops))

	// Global middleware stack: access log → security headers → routes
	handler := accessLog(securityHeaders(mux))

	srv := &http.Server{Addr: cfg.Addr, Handler: handler}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("postern %s (db: %s)", cfg.Addr, cfg.DBPath)
		if cfg.AgentSecret != "" {
			log.Printf("  /ops surface enabled")
		}
		if cfg.GatewayURL != "" {
			log.Printf("  control proxy → %s", cfg.GatewayURL)
		}
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(shutdownCtx)
	store.Close()
}

func loadConfig() *Config {
	c := &Config{
		Addr:          envOr("ADDR", ":8080"),
		DBPath:        envOr("DB_PATH", "postern.db"),
		AccessSecret:  mustEnv("JWT_ACCESS_SECRET"),
		RefreshSecret: mustEnv("JWT_REFRESH_SECRET"),
		AgentSecret:   os.Getenv("AGENT_PROVISIONING_SECRET"),
		GatewayURL:    os.Getenv("GATEWAY_URL"),
		GatewayToken:  os.Getenv("GATEWAY_TOKEN"),
		CookieSecure:  os.Getenv("ENVIRONMENT") == "production",
		WSAllowedOrigins: os.Getenv("WS_ALLOWED_ORIGINS"),
		Environment:   envOr("ENVIRONMENT", "development"),
	}
	if c.GatewayURL != "" && !isSafeURL(c.GatewayURL) {
		log.Fatal("GATEWAY_URL blocked by SSRF check")
	}
	if ips := os.Getenv("CONTROL_ALLOWED_IPS"); ips != "" {
		c.AllowedIPs = make(map[string]bool)
		for _, ip := range strings.Split(ips, ",") {
			c.AllowedIPs[strings.TrimSpace(ip)] = true
		}
	}
	return c
}

func mustEnv(k string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	log.Fatalf("%s required", k)
	return ""
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

var timeNow = time.Now // test seam for time-dependent logic
