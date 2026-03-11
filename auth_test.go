package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	cfg = &Config{
		Addr:          ":0",
		DBPath:        ":memory:",
		AccessSecret:  "test-access-secret",
		RefreshSecret: "test-refresh-secret",
		CookieSecure:  false,
		Environment:   "development",
	}
	initDB(cfg.DBPath)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", handleHealth)
	mux.Handle("POST /auth/register", http.HandlerFunc(handleRegister))
	mux.Handle("POST /auth/login", http.HandlerFunc(handleLogin))
	mux.Handle("POST /auth/logout", requireAuthMiddleware(http.HandlerFunc(handleLogout)))
	mux.Handle("POST /account/password", requireAuthMiddleware(http.HandlerFunc(handlePasswordChange)))
	mux.Handle("GET /account/me", requireAuthMiddleware(http.HandlerFunc(handleMe)))
	return httptest.NewServer(mux)
}

func jsonPost(url string, body any, cookies []*http.Cookie) (*http.Response, map[string]any) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Do(req)
	var result map[string]any
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(raw, &result)
	return resp, result
}

func jsonGet(url string, cookies []*http.Cookie) (*http.Response, map[string]any) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, _ := http.DefaultClient.Do(req)
	var result map[string]any
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	json.Unmarshal(raw, &result)
	return resp, result
}

func TestRegistrationAndLogin(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	// Register
	resp, body := jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "test@example.com", "password": "securepassword",
	}, nil)
	if resp.StatusCode != 201 {
		t.Fatalf("register: expected 201, got %d: %v", resp.StatusCode, body)
	}

	// Duplicate registration
	resp, _ = jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "test@example.com", "password": "anotherpassword",
	}, nil)
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate: expected 409, got %d", resp.StatusCode)
	}

	// Login
	resp, body = jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "test@example.com", "password": "securepassword",
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("login: expected 200, got %d: %v", resp.StatusCode, body)
	}
	cookies := resp.Cookies()
	if len(cookies) < 2 {
		t.Fatal("expected access_token and refresh_token cookies")
	}

	// Access protected route
	resp, body = jsonGet(srv.URL+"/account/me", cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("me: expected 200, got %d", resp.StatusCode)
	}
	uid, _ := body["userId"].(float64)
	if uid != 1 {
		t.Errorf("expected userId 1, got %v", body["userId"])
	}
}

func TestLoginWrongPassword(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "user@test.com", "password": "correctpass",
	}, nil)

	resp, body := jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "user@test.com", "password": "wrongpassword",
	}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d: %v", resp.StatusCode, body)
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	resp, _ := jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "nobody@test.com", "password": "anypassword1",
	}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "logout@test.com", "password": "password123",
	}, nil)
	resp, _ := jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "logout@test.com", "password": "password123",
	}, nil)
	cookies := resp.Cookies()

	// Logout
	resp, _ = jsonPost(srv.URL+"/auth/logout", nil, cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("logout: expected 200, got %d", resp.StatusCode)
	}

	// Session should be revoked — me should fail
	resp, _ = jsonGet(srv.URL+"/account/me", cookies)
	if resp.StatusCode == 200 {
		t.Error("expected auth failure after logout")
	}
}

func TestPasswordChange(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "pw@test.com", "password": "oldpassword1",
	}, nil)
	resp, _ := jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "pw@test.com", "password": "oldpassword1",
	}, nil)
	cookies := resp.Cookies()

	// Change password
	resp, body := jsonPost(srv.URL+"/account/password", map[string]string{
		"currentPassword": "oldpassword1", "newPassword": "newpassword2",
	}, cookies)
	if resp.StatusCode != 200 {
		t.Fatalf("password change: expected 200, got %d: %v", resp.StatusCode, body)
	}

	// Old session should be revoked
	resp, _ = jsonGet(srv.URL+"/account/me", cookies)
	if resp.StatusCode == 200 {
		t.Error("old session should be revoked after password change")
	}

	// Login with new password should work
	resp, _ = jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "pw@test.com", "password": "newpassword2",
	}, nil)
	if resp.StatusCode != 200 {
		t.Fatal("login with new password should succeed")
	}

	// Old password should fail
	resp, _ = jsonPost(srv.URL+"/auth/login", map[string]string{
		"email": "pw@test.com", "password": "oldpassword1",
	}, nil)
	if resp.StatusCode != 401 {
		t.Error("old password should fail after change")
	}
}

func TestUnauthenticatedAccess(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	resp, _ := jsonGet(srv.URL+"/account/me", nil)
	if resp.StatusCode != 401 {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

func TestValidation(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	// Short password
	resp, _ := jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "v@test.com", "password": "short",
	}, nil)
	if resp.StatusCode != 400 {
		t.Errorf("short password: expected 400, got %d", resp.StatusCode)
	}

	// Invalid email
	resp, _ = jsonPost(srv.URL+"/auth/register", map[string]string{
		"email": "notanemail", "password": "longenoughpassword",
	}, nil)
	if resp.StatusCode != 400 {
		t.Errorf("bad email: expected 400, got %d", resp.StatusCode)
	}
}

func TestContentNegotiation(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	// Without Accept: application/json, should redirect
	b, _ := json.Marshal(map[string]string{"email": "cn@test.com", "password": "password123"})
	req, _ := http.NewRequest("POST", srv.URL+"/auth/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, _ := client.Do(req)
	if resp.StatusCode != 302 {
		t.Errorf("expected redirect (302), got %d", resp.StatusCode)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
