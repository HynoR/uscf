package cmd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// useTunnelStateFile points the state file at a temp path for the duration of
// the test and returns it.
func useTunnelStateFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state")
	old := tunnelStateFilePath
	tunnelStateFilePath = path
	t.Cleanup(func() {
		tunnelStateFilePath = old
	})
	return path
}

func readTunnelState(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	return strings.TrimSpace(string(content))
}

func TestWriteTunnelState(t *testing.T) {
	path := useTunnelStateFile(t)

	if err := writeTunnelState(tunnelStateDown); err != nil {
		t.Fatalf("write down state: %v", err)
	}
	if got := readTunnelState(t, path); got != tunnelStateDown {
		t.Fatalf("state content = %q, want %q", got, tunnelStateDown)
	}

	if err := writeTunnelState(tunnelStateUp); err != nil {
		t.Fatalf("write up state: %v", err)
	}
	if got := readTunnelState(t, path); got != tunnelStateUp {
		t.Fatalf("state content = %q, want %q", got, tunnelStateUp)
	}
}

func TestWriteTunnelStateRejectsInvalidValue(t *testing.T) {
	useTunnelStateFile(t)

	if err := writeTunnelState("bad"); err == nil {
		t.Fatalf("expected invalid state to fail")
	}
}

// The state file is a container healthcheck hook. A plain CLI run must not
// create it — a hardcoded default is what made uscf litter a "tmp" directory
// at the root of the working drive on Windows (issue #12).
func TestWriteTunnelStateDisabledByDefault(t *testing.T) {
	dir := t.TempDir()
	old := tunnelStateFilePath
	tunnelStateFilePath = ""
	t.Cleanup(func() {
		tunnelStateFilePath = old
	})

	if err := writeTunnelState(tunnelStateUp); err != nil {
		t.Fatalf("disabled write should be a no-op, got %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("disabled state writer touched the filesystem: %v", entries)
	}

	// An invalid state is a programming error regardless of the feature flag.
	if err := writeTunnelState("bad"); err == nil {
		t.Fatalf("expected invalid state to fail even when disabled")
	}
}

// Writes come from the MASQUE callbacks, the WireGuard supervisor and the
// shutdown path concurrently; every one of them must leave a complete,
// well-formed file behind and no scratch file.
func TestWriteTunnelStateConcurrent(t *testing.T) {
	path := useTunnelStateFile(t)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		state := tunnelStateUp
		if i%2 == 0 {
			state = tunnelStateDown
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := writeTunnelState(state); err != nil {
				t.Errorf("concurrent write: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := readTunnelState(t, path); got != tunnelStateUp && got != tunnelStateDown {
		t.Fatalf("state content = %q, want a valid state", got)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("scratch file left behind: %v", err)
	}
}

// The healthcheck state must follow socksRuntime.SetTunnelUp for every
// transport. L4 used to serve without ever touching the state file, so
// healthcheck.sh saw a missing file and reported the container unhealthy
// forever even though the proxy worked.
func TestSocksRuntimePublishesTunnelState(t *testing.T) {
	path := useTunnelStateFile(t)

	runtime := newSocksRuntime(
		func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, nil },
		func(dialFunc socksDialFunc) socksServer { return nil },
	)

	// Constructing a runtime must clear any state left by a previous run.
	if got := readTunnelState(t, path); got != tunnelStateDown {
		t.Fatalf("state after construction = %q, want %q", got, tunnelStateDown)
	}

	runtime.SetTunnelUp(true)
	if got := readTunnelState(t, path); got != tunnelStateUp {
		t.Fatalf("state after tunnel up = %q, want %q", got, tunnelStateUp)
	}

	runtime.SetTunnelUp(false)
	if got := readTunnelState(t, path); got != tunnelStateDown {
		t.Fatalf("state after tunnel down = %q, want %q", got, tunnelStateDown)
	}
}
