package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HynoR/uscf/config"
)

func TestConsumeJWTFromSiblingFile(t *testing.T) {
	t.Run("missing jwt file returns empty token", func(t *testing.T) {
		configPath := filepath.Join(t.TempDir(), "config.json")

		got, err := consumeJWTFromSiblingFile(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("expected empty token, got %q", got)
		}
	})

	t.Run("blank jwt file returns empty token", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.json")
		jwtPath := filepath.Join(dir, "jwt.txt")
		if err := os.WriteFile(jwtPath, []byte(" \n\t"), 0o600); err != nil {
			t.Fatalf("failed to write jwt file: %v", err)
		}

		got, err := consumeJWTFromSiblingFile(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "" {
			t.Fatalf("expected empty token, got %q", got)
		}

		raw, err := os.ReadFile(jwtPath)
		if err != nil {
			t.Fatalf("failed to read jwt file: %v", err)
		}
		if string(raw) != " \n\t" {
			t.Fatalf("expected jwt file untouched when blank, got %q", string(raw))
		}
	})

	t.Run("non-empty jwt file returns token and truncates file", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.json")
		jwtPath := filepath.Join(dir, "jwt.txt")
		if err := os.WriteFile(jwtPath, []byte("  JWT-FROM-FILE \n"), 0o600); err != nil {
			t.Fatalf("failed to write jwt file: %v", err)
		}

		got, err := consumeJWTFromSiblingFile(configPath)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "JWT-FROM-FILE" {
			t.Fatalf("unexpected token: %q", got)
		}

		info, err := os.Stat(jwtPath)
		if err != nil {
			t.Fatalf("failed to stat jwt file: %v", err)
		}
		if info.Size() != 0 {
			t.Fatalf("expected truncated jwt file, size=%d", info.Size())
		}
	})

	t.Run("returns token even when truncation fails", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.json")
		jwtPath := filepath.Join(dir, "jwt.txt")
		if err := os.WriteFile(jwtPath, []byte("JWT-NOT-CLEARED"), 0o600); err != nil {
			t.Fatalf("failed to write jwt file: %v", err)
		}
		if err := os.Chmod(jwtPath, 0o400); err != nil {
			t.Fatalf("failed to chmod jwt file: %v", err)
		}

		got, err := consumeJWTFromSiblingFile(configPath)
		if err == nil {
			t.Fatalf("expected truncation error")
		}
		if got != "JWT-NOT-CLEARED" {
			t.Fatalf("expected token despite truncate failure, got %q", got)
		}
	})
}

func TestResolveJWTFromFlagOrFile(t *testing.T) {
	t.Run("free mode without jwt consumes jwt.txt and drives team registration", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.json")
		jwtPath := filepath.Join(dir, "jwt.txt")
		if err := os.WriteFile(jwtPath, []byte(" JWT-TEAM "), 0o600); err != nil {
			t.Fatalf("failed to write jwt file: %v", err)
		}

		cfg := config.Config{
			ID:          "device-id",
			AccessToken: "token",
			AccountMode: accountModeFree,
		}
		resolved, fromFile, err := resolveJWTFromFlagOrFile(configPath, true, cfg, "", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !fromFile {
			t.Fatalf("expected jwt from file")
		}
		if resolved != "JWT-TEAM" {
			t.Fatalf("unexpected resolved jwt: %q", resolved)
		}

		decision, err := decideStartupAction(true, cfg, "", resolved)
		if err != nil {
			t.Fatalf("unexpected decision error: %v", err)
		}
		if decision.Action != startupRegisterTeam {
			t.Fatalf("expected team registration action, got %q", decision.Action)
		}
		if decision.EffectiveMode != accountModeTeam {
			t.Fatalf("expected team mode, got %q", decision.EffectiveMode)
		}

		info, err := os.Stat(jwtPath)
		if err != nil {
			t.Fatalf("failed to stat jwt file: %v", err)
		}
		if info.Size() != 0 {
			t.Fatalf("expected consumed jwt file to be empty, size=%d", info.Size())
		}
	})

	t.Run("license present skips jwt file consumption", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "config.json")
		jwtPath := filepath.Join(dir, "jwt.txt")
		if err := os.WriteFile(jwtPath, []byte("JWT-SHOULD-STAY"), 0o600); err != nil {
			t.Fatalf("failed to write jwt file: %v", err)
		}

		cfg := config.Config{
			ID:          "device-id",
			AccessToken: "token",
			AccountMode: accountModeFree,
		}
		resolved, fromFile, err := resolveJWTFromFlagOrFile(configPath, true, cfg, "LICENSE-1", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if fromFile {
			t.Fatalf("expected jwt not from file")
		}
		if resolved != "" {
			t.Fatalf("expected empty resolved jwt, got %q", resolved)
		}

		raw, err := os.ReadFile(jwtPath)
		if err != nil {
			t.Fatalf("failed to read jwt file: %v", err)
		}
		if strings.TrimSpace(string(raw)) != "JWT-SHOULD-STAY" {
			t.Fatalf("expected jwt file unchanged, got %q", string(raw))
		}
	})
}
