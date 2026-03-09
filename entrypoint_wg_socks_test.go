package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type wgEntrypointHarness struct {
	repoRoot string
	etcDir   string
	binDir   string
	logPath  string
	mvState  string
}

func newWGEntrypointHarness(t *testing.T) wgEntrypointHarness {
	t.Helper()

	repoRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}

	tmpDir := t.TempDir()
	etcDir := filepath.Join(tmpDir, "etc")
	binDir := filepath.Join(tmpDir, "bin")
	logPath := filepath.Join(tmpDir, "stub.log")
	mvState := filepath.Join(tmpDir, "mv-state")

	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(etc): %v", err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(bin): %v", err)
	}

	writeExecutable(t, filepath.Join(binDir, "uscf"), `#!/bin/sh
set -eu
echo "uscf $*" >> "${STUB_LOG:?}"
case "$1" in
  wg)
    sub="$2"
    shift 2
    case "$sub" in
      register)
        if [ "${USCF_STUB_FAIL:-}" = "register" ]; then
          exit 17
        fi
        account_path=""
        while [ "$#" -gt 0 ]; do
          case "$1" in
            --wg-account)
              account_path="$2"
              shift 2
              ;;
            *)
              shift
              ;;
          esac
        done
        printf '{ "device_id": "dev", "access_token": "token", "license": "", "private_key": "key", "device_name": "", "model": "PC" }\n' > "$account_path"
        ;;
      generate)
        if [ "${USCF_STUB_FAIL:-}" = "generate" ]; then
          exit 23
        fi
        profile_path=""
        while [ "$#" -gt 0 ]; do
          case "$1" in
            --profile)
              profile_path="$2"
              shift 2
              ;;
            *)
              shift
              ;;
          esac
        done
        printf '[Interface]\nPrivateKey = key\nAddress = 172.16.0.2/32\nAddress = 2606:4700:110::2/128\n\n[Peer]\nPublicKey = peer\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\n' > "$profile_path"
        ;;
      *)
        exit 31
        ;;
    esac
    ;;
  socks)
    if [ "${USCF_STUB_FAIL:-}" = "socks" ]; then
      exit 29
    fi
    exit 0
    ;;
  *)
    exit 41
    ;;
esac
`)
	writeExecutable(t, filepath.Join(binDir, "wg-quick"), `#!/bin/sh
set -eu
echo "wg-quick $*" >> "${STUB_LOG:?}"
if [ "${WG_QUICK_STUB_FAIL:-}" = "$1" ]; then
  exit 19
fi
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "wg"), `#!/bin/sh
set -eu
echo "wg $*" >> "${STUB_LOG:?}"
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "mv"), `#!/bin/sh
set -eu
count=0
if [ -f "${MV_STUB_STATE:?}" ]; then
  count=$(cat "$MV_STUB_STATE")
fi
count=$((count + 1))
printf '%s' "$count" > "$MV_STUB_STATE"
if [ -n "${MV_STUB_FAIL_ON_CALL:-}" ] && [ "$MV_STUB_FAIL_ON_CALL" = "$count" ]; then
  exit 43
fi
exec /bin/mv "$@"
`)

	return wgEntrypointHarness{
		repoRoot: repoRoot,
		etcDir:   etcDir,
		binDir:   binDir,
		logPath:  logPath,
		mvState:  mvState,
	}
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func (h wgEntrypointHarness) run(t *testing.T, extraEnv ...string) (string, error) {
	t.Helper()

	cmd := exec.Command("sh", filepath.Join(h.repoRoot, "entrypoint-wg-socks.sh"))
	cmd.Dir = h.repoRoot
	cmd.Env = append(os.Environ(),
		"CONFIG_DIR="+h.etcDir,
		"PATH="+h.binDir+":"+os.Getenv("PATH"),
		"USCF_BIN="+filepath.Join(h.binDir, "uscf"),
		"WG_QUICK_BIN="+filepath.Join(h.binDir, "wg-quick"),
		"WG_BIN="+filepath.Join(h.binDir, "wg"),
		"STUB_LOG="+h.logPath,
		"MV_STUB_STATE="+h.mvState,
	)
	cmd.Env = append(cmd.Env, extraEnv...)

	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (h wgEntrypointHarness) readLog(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("ReadFile(log) error = %v", err)
	}
	return string(raw)
}

func TestWGEntrypointBootstrapsEmptyState(t *testing.T) {
	h := newWGEntrypointHarness(t)

	output, err := h.run(t)
	if err != nil {
		t.Fatalf("entrypoint error = %v, output:\n%s", err, output)
	}

	configPath := filepath.Join(h.etcDir, "config.json")
	accountPath := filepath.Join(h.etcDir, "wg-account.json")
	profilePath := filepath.Join(h.etcDir, "wgcf.conf")

	for _, path := range []string{configPath, accountPath, profilePath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	configRaw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile(config.json) error = %v", err)
	}
	configText := string(configRaw)
	for _, needle := range []string{`"bind_address": "0.0.0.0"`, `"port": "1080"`, `"username": ""`, `"password": ""`} {
		if !strings.Contains(configText, needle) {
			t.Fatalf("bootstrap config missing %q:\n%s", needle, configText)
		}
	}

	logText := h.readLog(t)
	for _, needle := range []string{"uscf wg register", "uscf wg generate", "wg-quick up", "wg show wgcf", "uscf socks"} {
		if !strings.Contains(logText, needle) {
			t.Fatalf("expected log to contain %q, got:\n%s", needle, logText)
		}
	}
}

func TestWGEntrypointStartsExistingDeploymentWithoutBootstrap(t *testing.T) {
	h := newWGEntrypointHarness(t)

	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\n"), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t)
	if err != nil {
		t.Fatalf("entrypoint error = %v, output:\n%s", err, output)
	}

	logText := h.readLog(t)
	if strings.Contains(logText, "uscf wg register") || strings.Contains(logText, "uscf wg generate") {
		t.Fatalf("existing deployment should not bootstrap:\n%s", logText)
	}
	for _, needle := range []string{"wg-quick up", "wg show wgcf", "uscf socks"} {
		if !strings.Contains(logText, needle) {
			t.Fatalf("expected log to contain %q, got:\n%s", needle, logText)
		}
	}
}

func TestWGEntrypointRejectsPartialState(t *testing.T) {
	tests := []struct {
		name  string
		files []string
	}{
		{name: "config-only", files: []string{"config.json"}},
		{name: "account-only", files: []string{"wg-account.json"}},
		{name: "profile-only", files: []string{"wgcf.conf"}},
		{name: "config-and-account", files: []string{"config.json", "wg-account.json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newWGEntrypointHarness(t)
			for _, name := range tt.files {
				if err := os.WriteFile(filepath.Join(h.etcDir, name), []byte("placeholder"), 0o600); err != nil {
					t.Fatalf("write %s: %v", name, err)
				}
			}

			output, err := h.run(t)
			if err == nil {
				t.Fatalf("expected entrypoint to reject partial state, output:\n%s", output)
			}
			if !strings.Contains(output, "partial deployment state") {
				t.Fatalf("expected partial state error, got:\n%s", output)
			}
		})
	}
}

func TestWGEntrypointCleansBootstrapTempsOnFailure(t *testing.T) {
	tests := []struct {
		name           string
		failStep       string
		mustContain    []string
		mustNotContain []string
	}{
		{
			name:           "register",
			failStep:       "register",
			mustContain:    []string{"uscf wg register"},
			mustNotContain: []string{"uscf wg generate", "wg-quick up", "uscf socks"},
		},
		{
			name:           "generate",
			failStep:       "generate",
			mustContain:    []string{"uscf wg register", "uscf wg generate"},
			mustNotContain: []string{"wg-quick up", "uscf socks"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newWGEntrypointHarness(t)

			output, err := h.run(t, "USCF_STUB_FAIL="+tt.failStep)
			if err == nil {
				t.Fatalf("expected %s failure, output:\n%s", tt.failStep, output)
			}

			entries, err := os.ReadDir(h.etcDir)
			if err != nil {
				t.Fatalf("ReadDir(etc) error = %v", err)
			}
			if len(entries) != 0 {
				var names []string
				for _, entry := range entries {
					names = append(names, entry.Name())
				}
				t.Fatalf("expected bootstrap failure to leave etc dir empty, got %v", names)
			}

			logText := h.readLog(t)
			for _, needle := range tt.mustContain {
				if !strings.Contains(logText, needle) {
					t.Fatalf("expected log to contain %q, got:\n%s", needle, logText)
				}
			}
			for _, needle := range tt.mustNotContain {
				if strings.Contains(logText, needle) {
					t.Fatalf("bootstrap failure should not reach %q:\n%s", needle, logText)
				}
			}
		})
	}
}

func TestWGEntrypointRollsBackPromotedFilesWhenCommitFails(t *testing.T) {
	h := newWGEntrypointHarness(t)

	output, err := h.run(t, "MV_STUB_FAIL_ON_CALL=2")
	if err == nil {
		t.Fatalf("expected commit failure, output:\n%s", output)
	}

	entries, err := os.ReadDir(h.etcDir)
	if err != nil {
		t.Fatalf("ReadDir(etc) error = %v", err)
	}
	if len(entries) != 0 {
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("expected commit failure to leave etc dir empty, got %v", names)
	}
}
