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
	upConfig string
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
	upConfig := filepath.Join(tmpDir, "wg-quick-up.conf")

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
        printf '[Interface]\nPrivateKey = key\nAddress = 172.16.0.2/32\nAddress = 2606:4700:110::2/128\nDNS = 1.1.1.1, 1.0.0.1\n\n[Peer]\nPublicKey = peer\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\n' > "$profile_path"
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
if [ "$1" = "up" ]; then
  cat "$2" > "${WG_QUICK_UP_CONFIG:?}"
fi
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "wg"), `#!/bin/sh
set -eu
echo "wg $*" >> "${STUB_LOG:?}"
exit 0
`)
	writeExecutable(t, filepath.Join(binDir, "ip"), `#!/bin/sh
set -eu
case "$*" in
  "-4 route show default")
    if [ -n "${IP_STUB_V4_ROUTE:-}" ]; then
      printf '%s\n' "$IP_STUB_V4_ROUTE"
    fi
    ;;
  "-4 addr show dev eth0 scope global")
    if [ -n "${IP_STUB_V4_ADDR:-}" ]; then
      printf '%s\n' "$IP_STUB_V4_ADDR"
    else
      printf '2: eth0    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0\n'
    fi
    ;;
  "-4 route get 1.1.1.1")
    if [ -n "${IP_STUB_V4_ROUTE_GET:-}" ]; then
      printf '%s\n' "$IP_STUB_V4_ROUTE_GET"
    else
      printf '1.1.1.1 via 172.18.0.1 dev eth0 src 172.18.0.2 uid 0\n'
    fi
    ;;
  "-6 route show default")
    if [ -n "${IP_STUB_V6_ROUTE:-}" ]; then
      printf '%s\n' "$IP_STUB_V6_ROUTE"
    fi
    ;;
  "-6 addr show dev eth0 scope global")
    if [ -n "${IP_STUB_V6_ADDR:-}" ]; then
      printf '%s\n' "$IP_STUB_V6_ADDR"
    fi
    ;;
  "-6 route get 2606:4700:4700::1111")
    if [ -n "${IP_STUB_V6_ROUTE_GET:-}" ]; then
      printf '%s\n' "$IP_STUB_V6_ROUTE_GET"
    fi
    ;;
  *)
    exit 2
    ;;
esac
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
		upConfig: upConfig,
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
		"IP_STUB_V4_ROUTE=default via 172.18.0.1 dev eth0",
		"USCF_BIN="+filepath.Join(h.binDir, "uscf"),
		"WG_QUICK_BIN="+filepath.Join(h.binDir, "wg-quick"),
		"WG_BIN="+filepath.Join(h.binDir, "wg"),
		"STUB_LOG="+h.logPath,
		"MV_STUB_STATE="+h.mvState,
		"WG_QUICK_UP_CONFIG="+h.upConfig,
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

func (h wgEntrypointHarness) readWGQuickUpConfig(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.upConfig)
	if err != nil {
		t.Fatalf("ReadFile(wg-quick up config) error = %v", err)
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

	profileRaw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("ReadFile(wgcf.conf) error = %v", err)
	}
	if !strings.Contains(string(profileRaw), "DNS = 1.1.1.1, 1.0.0.1") {
		t.Fatalf("expected persisted wgcf.conf to keep DNS line:\n%s", string(profileRaw))
	}

	runtimeProfile := h.readWGQuickUpConfig(t)
	if strings.Contains(runtimeProfile, "DNS = ") {
		t.Fatalf("expected bootstrap runtime profile to strip DNS lines:\n%s", runtimeProfile)
	}
	for _, needle := range []string{
		"PostUp = ip rule add from 172.18.0.2/32 lookup main",
		"PostDown = ip rule delete from 172.18.0.2/32 lookup main",
	} {
		if !strings.Contains(runtimeProfile, needle) {
			t.Fatalf("expected bootstrap runtime profile to contain %q:\n%s", needle, runtimeProfile)
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
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\nDNS = 1.1.1.1, 1.0.0.1\n"), 0o600); err != nil {
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
	if !strings.Contains(logText, "wg-quick down wgcf") {
		t.Fatalf("expected wg-quick down to use interface name, got:\n%s", logText)
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

func TestWGEntrypointSanitizesDNSForRuntimeCopy(t *testing.T) {
	h := newWGEntrypointHarness(t)

	profilePath := filepath.Join(h.etcDir, "wgcf.conf")
	originalProfile := "[Interface]\nPrivateKey = key\nAddress = 172.16.0.2/32\nDNS = 1.1.1.1, 1.0.0.1\n\n[Peer]\nPublicKey = peer\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\n"
	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(profilePath, []byte(originalProfile), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t)
	if err != nil {
		t.Fatalf("entrypoint error = %v, output:\n%s", err, output)
	}

	runtimeProfile := h.readWGQuickUpConfig(t)
	if strings.Contains(runtimeProfile, "DNS = ") {
		t.Fatalf("expected runtime profile to strip DNS lines:\n%s", runtimeProfile)
	}
	for _, needle := range []string{
		"PostUp = ip rule add from 172.18.0.2/32 lookup main",
		"PostDown = ip rule delete from 172.18.0.2/32 lookup main",
	} {
		if !strings.Contains(runtimeProfile, needle) {
			t.Fatalf("expected runtime profile to contain %q:\n%s", needle, runtimeProfile)
		}
	}

	persistedProfileRaw, err := os.ReadFile(profilePath)
	if err != nil {
		t.Fatalf("ReadFile(wgcf.conf) error = %v", err)
	}
	if string(persistedProfileRaw) != originalProfile {
		t.Fatalf("expected persisted wgcf.conf to remain unchanged:\nwant:\n%s\ngot:\n%s", originalProfile, string(persistedProfileRaw))
	}
}

func TestWGEntrypointAddsIPv6RouteGuardWhenAvailable(t *testing.T) {
	h := newWGEntrypointHarness(t)

	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\n\n[Peer]\nPublicKey = peer\nEndpoint = engage.cloudflareclient.com:2408\nAllowedIPs = 0.0.0.0/0, ::/0\n"), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t,
		"IP_STUB_V6_ROUTE=default via fe80::1 dev eth0",
		"IP_STUB_V6_ROUTE_GET=2606:4700:4700::1111 from :: via fe80::1 dev eth0 src 2606:4700:110:8910:c1ce:4bcb:cc6f:a848 metric 1024",
	)
	if err != nil {
		t.Fatalf("entrypoint error = %v, output:\n%s", err, output)
	}

	runtimeProfile := h.readWGQuickUpConfig(t)
	for _, needle := range []string{
		"PostUp = ip -6 rule add from 2606:4700:110:8910:c1ce:4bcb:cc6f:a848/128 lookup main",
		"PostDown = ip -6 rule delete from 2606:4700:110:8910:c1ce:4bcb:cc6f:a848/128 lookup main",
	} {
		if !strings.Contains(runtimeProfile, needle) {
			t.Fatalf("expected runtime profile to contain %q:\n%s", needle, runtimeProfile)
		}
	}
}

func TestWGEntrypointFailsWithoutIPv4DefaultRoute(t *testing.T) {
	h := newWGEntrypointHarness(t)

	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\n"), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t, "IP_STUB_V4_ROUTE=")
	if err == nil {
		t.Fatalf("expected missing IPv4 default route to fail, output:\n%s", output)
	}
	if !strings.Contains(output, "failed to detect default IPv4 route") {
		t.Fatalf("expected IPv4 default route error, got:\n%s", output)
	}

	logText := h.readLog(t)
	if strings.Contains(logText, "wg-quick up") {
		t.Fatalf("entrypoint should fail before wg-quick up:\n%s", logText)
	}
}

func TestWGEntrypointFailsWithoutIPv4SourceAddress(t *testing.T) {
	h := newWGEntrypointHarness(t)

	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\n"), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t, "IP_STUB_V4_ROUTE_GET=1.1.1.1 via 172.18.0.1 dev eth0 uid 0")
	if err == nil {
		t.Fatalf("expected missing IPv4 source address to fail, output:\n%s", output)
	}
	if !strings.Contains(output, "failed to detect source IPv4 address") {
		t.Fatalf("expected IPv4 source address error, got:\n%s", output)
	}
}

func TestWGEntrypointRemovesRuntimeConfigOnExit(t *testing.T) {
	h := newWGEntrypointHarness(t)

	runtimePath := filepath.Join(h.etcDir, "runtime", "wgcf.conf")
	if err := os.MkdirAll(filepath.Dir(runtimePath), 0o755); err != nil {
		t.Fatalf("MkdirAll(runtime dir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\n"), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t, "WG_RUNTIME_CONFIG_PATH="+runtimePath)
	if err != nil {
		t.Fatalf("entrypoint error = %v, output:\n%s", err, output)
	}

	if _, err := os.Stat(runtimePath); !os.IsNotExist(err) {
		t.Fatalf("expected runtime config to be removed, stat error = %v", err)
	}
}

func TestWGEntrypointUsesKernelSelectedIPv4SourceForRouteGuard(t *testing.T) {
	h := newWGEntrypointHarness(t)

	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\n"), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t,
		"IP_STUB_V4_ADDR=2: eth0    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0\n2: eth0    inet 172.18.0.99/16 brd 172.18.255.255 scope global secondary eth0",
		"IP_STUB_V4_ROUTE_GET=1.1.1.1 via 172.18.0.1 dev eth0 src 172.18.0.99 uid 0",
	)
	if err != nil {
		t.Fatalf("entrypoint error = %v, output:\n%s", err, output)
	}

	runtimeProfile := h.readWGQuickUpConfig(t)
	if !strings.Contains(runtimeProfile, "PostUp = ip rule add from 172.18.0.99/32 lookup main") {
		t.Fatalf("expected runtime profile to use kernel-selected IPv4 source:\n%s", runtimeProfile)
	}
	if strings.Contains(runtimeProfile, "PostUp = ip rule add from 172.18.0.2/32 lookup main") {
		t.Fatalf("runtime profile used first global IPv4 instead of route-selected source:\n%s", runtimeProfile)
	}
}

func TestWGEntrypointRejectsRuntimeConfigBasenameMismatch(t *testing.T) {
	h := newWGEntrypointHarness(t)

	if err := os.WriteFile(filepath.Join(h.etcDir, "config.json"), []byte(`{"socks":{"bind_address":"0.0.0.0","port":"1080","username":"","password":""}}`), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.etcDir, "wgcf.conf"), []byte("[Interface]\nPrivateKey = key\n"), 0o600); err != nil {
		t.Fatalf("write wgcf.conf: %v", err)
	}

	output, err := h.run(t, "WG_RUNTIME_CONFIG_PATH="+filepath.Join(h.etcDir, "runtime", "wrong-name.conf"))
	if err == nil {
		t.Fatalf("expected basename mismatch to fail, output:\n%s", output)
	}
	if !strings.Contains(output, "must end with /wgcf.conf") {
		t.Fatalf("expected runtime config basename error, got:\n%s", output)
	}
}
