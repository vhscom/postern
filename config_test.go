package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joho/godotenv"
)

func TestGodotenvBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("TEST_DOTENV_KEY=hello\n"), 0600)

	os.Unsetenv("TEST_DOTENV_KEY")
	godotenv.Load(path)

	if v := os.Getenv("TEST_DOTENV_KEY"); v != "hello" {
		t.Errorf("got %q, want %q", v, "hello")
	}
	os.Unsetenv("TEST_DOTENV_KEY")
}

func TestGodotenvExistingEnvTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("TEST_DOTENV_PRIO=fromfile\n"), 0600)

	os.Setenv("TEST_DOTENV_PRIO", "fromenv")
	defer os.Unsetenv("TEST_DOTENV_PRIO")
	godotenv.Load(path)

	if v := os.Getenv("TEST_DOTENV_PRIO"); v != "fromenv" {
		t.Errorf("got %q, want %q (env should take precedence)", v, "fromenv")
	}
}

func TestGodotenvQuotedValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("TEST_DQ=\"double quoted\"\nTEST_SQ='single quoted'\n"), 0600)

	os.Unsetenv("TEST_DQ")
	os.Unsetenv("TEST_SQ")
	godotenv.Load(path)

	if v := os.Getenv("TEST_DQ"); v != "double quoted" {
		t.Errorf("double quoted: got %q", v)
	}
	if v := os.Getenv("TEST_SQ"); v != "single quoted" {
		t.Errorf("single quoted: got %q", v)
	}
	os.Unsetenv("TEST_DQ")
	os.Unsetenv("TEST_SQ")
}

func TestGodotenvExportPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("export TEST_EXPORT_KEY=exported\n"), 0600)

	os.Unsetenv("TEST_EXPORT_KEY")
	godotenv.Load(path)

	if v := os.Getenv("TEST_EXPORT_KEY"); v != "exported" {
		t.Errorf("got %q, want %q", v, "exported")
	}
	os.Unsetenv("TEST_EXPORT_KEY")
}

func TestGodotenvMissingFile(t *testing.T) {
	// Should return error but not panic
	err := godotenv.Load("/nonexistent/path/.env")
	if err == nil {
		t.Error("expected error for missing file")
	}
}
