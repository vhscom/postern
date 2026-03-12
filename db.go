package main

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

var store *sql.DB

func initDB(path string) {
	var err error
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	if path == ":memory:" {
		dsn = ":memory:?_pragma=foreign_keys(1)"
	}
	store, err = sql.Open("sqlite", dsn)
	if err != nil {
		log.Fatal(err)
	}
	store.SetMaxOpenConns(1) // SQLite single-writer
	migrate()
}

func migrate() {
	// Version tracking — allows future ALTER TABLE migrations
	store.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT DEFAULT (datetime('now')))`)
	var currentVersion int
	store.QueryRow("SELECT COALESCE(MAX(version), 0) FROM schema_version").Scan(&currentVersion)

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS account (
			id INTEGER PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			password_data TEXT NOT NULL,
			created_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS session (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL REFERENCES account(id),
			user_agent TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_session_user ON session(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_session_expiry ON session(expires_at)`,
		`CREATE INDEX IF NOT EXISTS idx_session_user_expiry ON session(user_id, expires_at)`,
		`CREATE TABLE IF NOT EXISTS security_event (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			type TEXT NOT NULL,
			ip_address TEXT NOT NULL,
			user_id INTEGER,
			user_agent TEXT,
			status INTEGER,
			detail TEXT,
			created_at TEXT DEFAULT (datetime('now')),
			actor_id TEXT NOT NULL DEFAULT 'app:postern'
		)`,
		`CREATE INDEX IF NOT EXISTS idx_event_type ON security_event(type)`,
		`CREATE INDEX IF NOT EXISTS idx_event_created ON security_event(created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_event_user ON security_event(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_event_ip ON security_event(ip_address)`,
		`CREATE TABLE IF NOT EXISTS agent_credential (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			key_hash TEXT NOT NULL,
			trust_level TEXT NOT NULL DEFAULT 'read' CHECK (trust_level IN ('read','write')),
			description TEXT,
			created_at TEXT DEFAULT (datetime('now')),
			revoked_at TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_active ON agent_credential(name) WHERE revoked_at IS NULL`,
		`CREATE TABLE IF NOT EXISTS user_peer (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES account(id),
			label TEXT NOT NULL DEFAULT 'default',
			endpoint TEXT NOT NULL,
			wg_pubkey TEXT NOT NULL,
			created_at TEXT DEFAULT (datetime('now')),
			updated_at TEXT DEFAULT (datetime('now')),
			UNIQUE(user_id, label)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_peer_user ON user_peer(user_id)`,
		`CREATE TABLE IF NOT EXISTS user_subscription (
			user_id INTEGER PRIMARY KEY REFERENCES account(id),
			stripe_customer_id TEXT UNIQUE,
			tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'team')),
			current_period_end TEXT,
			created_at TEXT DEFAULT (datetime('now')),
			updated_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS subscription_history (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES account(id),
			tier_from TEXT NOT NULL,
			tier_to TEXT NOT NULL,
			reason TEXT NOT NULL,
			created_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sub_history_user ON subscription_history(user_id)`,
	}
	for _, s := range stmts {
		if _, err := store.Exec(s); err != nil {
			log.Fatalf("migrate: %v\n%s", err, s)
		}
	}

	// v3: Node management for WireGuard control plane
	if currentVersion < 3 {
		v3 := []string{
			`ALTER TABLE agent_credential ADD COLUMN user_id INTEGER REFERENCES account(id)`,
			`ALTER TABLE user_peer ADD COLUMN allowed_ips TEXT NOT NULL DEFAULT '10.0.0.0/24'`,
			`ALTER TABLE user_peer ADD COLUMN persistent_keepalive INTEGER NOT NULL DEFAULT 0`,
			`ALTER TABLE user_peer ADD COLUMN version INTEGER NOT NULL DEFAULT 1`,
			`CREATE TABLE IF NOT EXISTS user_node (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				user_id INTEGER NOT NULL REFERENCES account(id),
				label TEXT NOT NULL,
				wg_pubkey TEXT NOT NULL,
				wg_endpoint TEXT,
				wg_listen_port INTEGER NOT NULL DEFAULT 51820,
				allowed_ips TEXT NOT NULL DEFAULT '10.0.0.0/32',
				persistent_keepalive INTEGER NOT NULL DEFAULT 25,
				interface_name TEXT NOT NULL DEFAULT 'wg0',
				agent_credential_id INTEGER REFERENCES agent_credential(id),
				last_seen_at TEXT,
				last_status TEXT,
				created_at TEXT DEFAULT (datetime('now')),
				updated_at TEXT DEFAULT (datetime('now')),
				UNIQUE(user_id, label)
			)`,
			`CREATE INDEX IF NOT EXISTS idx_node_user ON user_node(user_id)`,
			`CREATE INDEX IF NOT EXISTS idx_node_agent ON user_node(agent_credential_id)`,
		}
		for _, s := range v3 {
			if _, err := store.Exec(s); err != nil {
				log.Fatalf("migrate v3: %v\n%s", err, s)
			}
		}
	}

	// v4: STUN endpoint discovery source tracking
	if currentVersion < 4 {
		v4 := []string{
			`ALTER TABLE user_node ADD COLUMN wg_endpoint_source TEXT NOT NULL DEFAULT 'manual'`,
		}
		for _, s := range v4 {
			if _, err := store.Exec(s); err != nil {
				log.Fatalf("migrate v4: %v\n%s", err, s)
			}
		}
	}

	// Record schema version (bump this number when adding migrations above)
	const schemaVersion = 4
	if currentVersion < schemaVersion {
		store.Exec("INSERT OR IGNORE INTO schema_version (version) VALUES (?)", schemaVersion)
	}
}
