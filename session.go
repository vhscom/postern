package main

import (
	"database/sql"
	"time"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

const (
	sessionDuration = 7 * 24 * time.Hour
	maxSessions     = 3
)

type Session struct {
	ID        string
	UserID    int
	UserAgent string
	IPAddress string
	ExpiresAt time.Time
	CreatedAt time.Time
}

func createSession(userID int, ua, ip string) (string, error) {
	if _, err := store.Exec("DELETE FROM session WHERE expires_at < datetime('now')"); err != nil {
		logError("session.cleanup", err)
	}

	id, err := gonanoid.New()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	expires := now.Add(sessionDuration)

	_, err = store.Exec(
		"INSERT INTO session (id, user_id, user_agent, ip_address, expires_at, created_at) VALUES (?,?,?,?,?,?)",
		id, userID, ua, ip, expires.Format(time.RFC3339), now.Format(time.RFC3339),
	)
	if err != nil {
		return "", err
	}
	enforceSessionLimit(userID)
	return id, nil
}

func enforceSessionLimit(userID int) {
	rows, err := store.Query(
		"SELECT id FROM session WHERE user_id = ? AND expires_at > datetime('now') ORDER BY created_at DESC",
		userID,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	for i := maxSessions; i < len(ids); i++ {
		if _, err := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE id = ?", ids[i]); err != nil {
			logError("session.enforce_limit", err)
		}
	}
}

func getSession(sid string) (*Session, error) {
	var s Session
	var expiresAt, createdAt string
	err := store.QueryRow(
		"SELECT id, user_id, user_agent, ip_address, expires_at, created_at FROM session WHERE id = ? AND expires_at > datetime('now')",
		sid,
	).Scan(&s.ID, &s.UserID, &s.UserAgent, &s.IPAddress, &expiresAt, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAt)
	s.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)

	// Sliding expiration
	newExpiry := time.Now().UTC().Add(sessionDuration)
	if _, err = store.Exec("UPDATE session SET expires_at = ? WHERE id = ?", newExpiry.Format(time.RFC3339), sid); err != nil {
		logError("session.slide_expiry", err)
	}
	return &s, nil
}

func endSession(sid string) {
	if _, err := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE id = ?", sid); err != nil {
		logError("session.end", err)
	}
}

func endAllSessions(userID int) {
	if _, err := store.Exec("UPDATE session SET expires_at = datetime('now') WHERE user_id = ? AND expires_at > datetime('now')", userID); err != nil {
		logError("session.end_all", err)
	}
}
