package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// --- Event broadcast (wakes subscription goroutines immediately) ---

var eventBroadcast struct {
	mu sync.Mutex
	ch chan struct{}
}

func init() {
	eventBroadcast.ch = make(chan struct{})
}

// eventSignal returns a channel that closes when the next event is emitted.
func eventSignal() <-chan struct{} {
	eventBroadcast.mu.Lock()
	defer eventBroadcast.mu.Unlock()
	return eventBroadcast.ch
}

func notifySubscribers() {
	eventBroadcast.mu.Lock()
	close(eventBroadcast.ch)
	eventBroadcast.ch = make(chan struct{})
	eventBroadcast.mu.Unlock()
}

// --- Security event logging ---

func emitEvent(eventType, ip string, userID int, ua string, status int, detail map[string]any) {
	var detailJSON *string
	if detail != nil {
		b, _ := json.Marshal(detail)
		s := string(b)
		detailJSON = &s
	}
	var uid *int
	if userID > 0 {
		uid = &userID
	}
	_, err := store.Exec(
		"INSERT INTO security_event (type, ip_address, user_id, user_agent, status, detail) VALUES (?,?,?,?,?,?)",
		eventType, ip, uid, ua, status, detailJSON,
	)
	if err != nil {
		logError("event."+eventType, err)
		return
	}
	notifySubscribers()
}

// --- Adaptive proof-of-work challenges ---

const (
	challengeWindow    = 15 // minutes
	challengeThreshold = 3  // failures before challenge
	lowDifficulty      = 3  // leading hex zeros
	highDifficulty     = 5
	highThreshold      = 6
	challengeMaxAge    = 5 * time.Minute
)

type Challenge struct {
	Type       string `json:"type"`
	Difficulty int    `json:"difficulty"`
	Nonce      string `json:"nonce"`
}

// computeChallenge checks recent failure events for the IP and returns a PoW challenge if threshold exceeded.
func computeChallenge(ip, secret string) *Challenge {
	var count int
	err := store.QueryRow(
		"SELECT COUNT(*) FROM security_event WHERE type IN ('login.failure','challenge.issued','challenge.failed') AND ip_address = ? AND created_at >= datetime('now', ?)",
		ip, fmt.Sprintf("-%d minutes", challengeWindow),
	).Scan(&count)
	if err != nil || count < challengeThreshold {
		return nil
	}
	diff := lowDifficulty
	if count >= highThreshold {
		diff = highDifficulty
	}
	return &Challenge{
		Type:       "pow",
		Difficulty: diff,
		Nonce:      buildSignedNonce(secret, ip),
	}
}

// buildSignedNonce creates "random.timestamp.hmac" bound to client IP.
func buildSignedNonce(secret, ip string) string {
	random := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmacSHA256(secret, random+"|"+ts+"|"+ip)
	return random + "." + ts + "." + mac
}

// verifySignedNonce validates a nonce and checks IP binding + expiry.
func verifySignedNonce(nonce, secret, ip string) bool {
	parts := strings.SplitN(nonce, ".", 3)
	if len(parts) != 3 {
		return false
	}
	random, tsStr, mac := parts[0], parts[1], parts[2]
	expected := hmacSHA256(secret, random+"|"+tsStr+"|"+ip)
	if subtle.ConstantTimeCompare([]byte(mac), []byte(expected)) != 1 {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	age := time.Since(time.Unix(ts, 0))
	return age >= 0 && age <= challengeMaxAge
}

// verifySolution checks that SHA-256(nonce+solution) has the required leading zeros.
func verifySolution(nonce, solution string, difficulty int) bool {
	hash := fmt.Sprintf("%x", sha256Digest([]byte(nonce+solution)))
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}
