package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// POST /auth/register
func handleRegister(w http.ResponseWriter, r *http.Request) {
	email, password := parseCredentials(r)
	if !validEmail(email) || !validPassword(password) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid email or password")
		return
	}
	hash, err := hashPassword(password)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Registration failed")
		return
	}
	domain := maskEmail(email)
	_, err = store.Exec("INSERT INTO account (email, password_data) VALUES (?,?)", email, hash)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			emitEvent("registration.failure", clientIP(r), 0, r.UserAgent(), 409, map[string]any{"email": domain})
			respondError(w, r, http.StatusConflict, "EMAIL_EXISTS", "Registration failed")
			return
		}
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Registration failed")
		return
	}
	emitEvent("registration.success", clientIP(r), 0, r.UserAgent(), 201, map[string]any{"email": domain})
	respondSuccess(w, r, http.StatusCreated, "Registration successful", "/#registered")
}

// POST /auth/login
func handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	// Adaptive PoW challenge
	ch := computeChallenge(ip, cfg.AccessSecret)
	if ch != nil {
		nonce, solution := extractChallenge(r)
		if nonce == "" || solution == "" {
			emitEvent("challenge.issued", ip, 0, r.UserAgent(), 403, map[string]any{"difficulty": ch.Difficulty})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error":     "Proof of work required",
				"code":      "CHALLENGE_REQUIRED",
				"challenge": ch,
			})
			return
		}
		if !verifySignedNonce(nonce, cfg.AccessSecret, ip) || !verifySolution(nonce, solution, ch.Difficulty) {
			emitEvent("challenge.failed", ip, 0, r.UserAgent(), 403, nil)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error":     "Invalid proof of work",
				"code":      "CHALLENGE_FAILED",
				"challenge": ch,
			})
			return
		}
	}

	email, password := parseCredentials(r)
	domain := maskEmail(email)

	var userID int
	var storedHash string
	err := store.QueryRow("SELECT id, password_data FROM account WHERE email = ?", email).Scan(&userID, &storedHash)
	if err != nil {
		rejectConstantTime(password)
		emitEvent("login.failure", ip, 0, r.UserAgent(), 401, map[string]any{"email": domain})
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}
	if !verifyPassword(password, storedHash) {
		emitEvent("login.failure", ip, userID, r.UserAgent(), 401, map[string]any{"email": domain})
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	sid, err := createSession(userID, r.UserAgent(), ip)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Login failed")
		return
	}
	if err := setTokenCookies(w, userID, sid); err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Login failed")
		return
	}
	emitEvent("login.success", ip, userID, r.UserAgent(), 200, map[string]any{"sessionId": sid})
	respondSuccess(w, r, http.StatusOK, "Login successful", "/#logged-in")
}

// POST /auth/logout
func handleLogout(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	endSession(claims.SID)
	clearTokenCookies(w)
	emitEvent("session.revoke", clientIP(r), claims.UID, r.UserAgent(), 200, map[string]any{"sessionId": claims.SID})
	respondSuccess(w, r, http.StatusOK, "Logged out", "/#logged-out")
}

// POST /account/password
func handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	current, newPw := parsePasswordChange(r)
	if !validPassword(current) || !validPassword(newPw) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "Invalid password")
		return
	}
	if normalizePassword(current) == normalizePassword(newPw) {
		respondError(w, r, http.StatusBadRequest, "VALIDATION_ERROR", "New password must differ from current")
		return
	}

	var storedHash string
	err := store.QueryRow("SELECT password_data FROM account WHERE id = ?", claims.UID).Scan(&storedHash)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Password change failed")
		return
	}
	if !verifyPassword(current, storedHash) {
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Current password is incorrect")
		return
	}

	hash, err := hashPassword(newPw)
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Password change failed")
		return
	}
	if _, err = store.Exec("UPDATE account SET password_data = ? WHERE id = ?", hash, claims.UID); err != nil {
		logError("account.password_update", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Password change failed")
		return
	}

	endAllSessions(claims.UID)
	clearTokenCookies(w)
	emitEvent("password.change", clientIP(r), claims.UID, r.UserAgent(), 200, map[string]any{"sessionId": claims.SID})
	emitEvent("session.revoke_all", clientIP(r), claims.UID, r.UserAgent(), 200, nil)
	respondSuccess(w, r, http.StatusOK, "Password changed", "/#password-changed")
}

// GET /account/me
func handleMe(w http.ResponseWriter, r *http.Request) {
	claims := getClaims(r)
	jsonOK(w, map[string]any{"userId": claims.UID})
}

// GET /health
func handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	code := http.StatusOK
	if err := store.Ping(); err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}
	w.WriteHeader(code)
	jsonOK(w, map[string]any{"status": status, "timestamp": fmt.Sprintf("%d", nowUnix())})
}

func extractChallenge(r *http.Request) (nonce, solution string) {
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		// Body was already partially consumed by parseCredentials if called before.
		// For login, challenge extraction must happen first. Use query params as fallback.
		nonce = r.URL.Query().Get("challengeNonce")
		solution = r.URL.Query().Get("challengeSolution")
		if nonce == "" {
			// Try to peek at raw body — but since JSON body is consumed once,
			// the caller sends nonce/solution as query params or in the JSON body.
			// For simplicity, we support query params for challenge fields.
		}
		return
	}
	r.ParseForm()
	return r.FormValue("challengeNonce"), r.FormValue("challengeSolution")
}

func nowUnix() int64 {
	return timeNow().Unix()
}

