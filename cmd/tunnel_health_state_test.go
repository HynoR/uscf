package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTunnelState(t *testing.T) {
	oldPath := tunnelStateFilePath
	tunnelStateFilePath = filepath.Join(t.TempDir(), "state")
	t.Cleanup(func() {
		tunnelStateFilePath = oldPath
	})

	if err := writeTunnelState(tunnelStateDown); err != nil {
		t.Fatalf("write down state: %v", err)
	}
	content, err := os.ReadFile(tunnelStateFilePath)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	if got := strings.TrimSpace(string(content)); got != tunnelStateDown {
		t.Fatalf("state content = %q, want %q", got, tunnelStateDown)
	}

	if err := writeTunnelState(tunnelStateUp); err != nil {
		t.Fatalf("write up state: %v", err)
	}
	content, err = os.ReadFile(tunnelStateFilePath)
	if err != nil {
		t.Fatalf("read state file second time: %v", err)
	}
	if got := strings.TrimSpace(string(content)); got != tunnelStateUp {
		t.Fatalf("state content = %q, want %q", got, tunnelStateUp)
	}
}

func TestWriteTunnelStateRejectsInvalidValue(t *testing.T) {
	oldPath := tunnelStateFilePath
	tunnelStateFilePath = filepath.Join(t.TempDir(), "state")
	t.Cleanup(func() {
		tunnelStateFilePath = oldPath
	})

	if err := writeTunnelState("bad"); err == nil {
		t.Fatalf("expected invalid state to fail")
	}
}
