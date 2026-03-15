package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotenvBasic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("TEST_DOTENV_KEY=hello\n"), 0600)

	os.Unsetenv("TEST_DOTENV_KEY")
	loadDotenv(path)

	if v := os.Getenv("TEST_DOTENV_KEY"); v != "hello" {
		t.Errorf("got %q, want %q", v, "hello")
	}
	os.Unsetenv("TEST_DOTENV_KEY")
}

func TestLoadDotenvExistingEnvTakesPrecedence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("TEST_DOTENV_PRIO=fromfile\n"), 0600)

	os.Setenv("TEST_DOTENV_PRIO", "fromenv")
	defer os.Unsetenv("TEST_DOTENV_PRIO")
	loadDotenv(path)

	if v := os.Getenv("TEST_DOTENV_PRIO"); v != "fromenv" {
		t.Errorf("got %q, want %q (env should take precedence)", v, "fromenv")
	}
}

func TestLoadDotenvQuotedValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte(`
TEST_DQ="double quoted"
TEST_SQ='single quoted'
`), 0600)

	os.Unsetenv("TEST_DQ")
	os.Unsetenv("TEST_SQ")
	loadDotenv(path)

	if v := os.Getenv("TEST_DQ"); v != "double quoted" {
		t.Errorf("double quoted: got %q", v)
	}
	if v := os.Getenv("TEST_SQ"); v != "single quoted" {
		t.Errorf("single quoted: got %q", v)
	}
	os.Unsetenv("TEST_DQ")
	os.Unsetenv("TEST_SQ")
}

func TestLoadDotenvExportPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("export TEST_EXPORT_KEY=exported\n"), 0600)

	os.Unsetenv("TEST_EXPORT_KEY")
	loadDotenv(path)

	if v := os.Getenv("TEST_EXPORT_KEY"); v != "exported" {
		t.Errorf("got %q, want %q", v, "exported")
	}
	os.Unsetenv("TEST_EXPORT_KEY")
}

func TestLoadDotenvSkipsComments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	os.WriteFile(path, []byte("# comment\nTEST_COMMENT_KEY=value\n"), 0600)

	os.Unsetenv("TEST_COMMENT_KEY")
	loadDotenv(path)

	if v := os.Getenv("TEST_COMMENT_KEY"); v != "value" {
		t.Errorf("got %q, want %q", v, "value")
	}
	os.Unsetenv("TEST_COMMENT_KEY")
}

func TestLoadDotenvMissingFile(t *testing.T) {
	// Should not panic on missing file
	loadDotenv("/nonexistent/path/.env")
}
