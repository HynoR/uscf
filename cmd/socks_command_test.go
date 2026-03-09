package cmd

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HynoR/uscf/config"
	"github.com/spf13/cobra"
)

func newSocksCmdForTest() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().StringP("config", "c", "", "")
	cmd.Flags().StringP("bind-address", "b", "", "")
	cmd.Flags().StringP("port", "p", "", "")
	cmd.Flags().StringP("username", "u", "", "")
	cmd.Flags().StringP("password", "w", "", "")
	return cmd
}

func TestRootRegistersSocksCommand(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"socks"})
	if err != nil {
		t.Fatalf("Find(socks) error = %v", err)
	}
	if cmd == nil || cmd.Name() != "socks" {
		t.Fatalf("expected socks command, got %#v", cmd)
	}
}

func TestRunSocksCmdUsesConfigWithoutKeyMaterial(t *testing.T) {
	oldPrepare := prepareDirectSocksRuntimeFunc
	oldRunServer := runSocksServerFunc
	oldConfig := config.AppConfig
	oldLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		prepareDirectSocksRuntimeFunc = oldPrepare
		runSocksServerFunc = oldRunServer
		config.AppConfig = oldConfig
		config.ConfigLoaded = oldLoaded
	})

	config.AppConfig = config.Config{
		Socks:   config.GetDefaultSocksConfig(),
		Logging: config.GetDefaultLoggingConfig(),
	}
	config.ConfigLoaded = true

	cmd := newSocksCmdForTest()
	if err := cmd.Flags().Set("bind-address", "0.0.0.0"); err != nil {
		t.Fatalf("set bind-address: %v", err)
	}
	if err := cmd.Flags().Set("port", "2333"); err != nil {
		t.Fatalf("set port: %v", err)
	}
	if err := cmd.Flags().Set("username", "alice"); err != nil {
		t.Fatalf("set username: %v", err)
	}
	if err := cmd.Flags().Set("password", "secret"); err != nil {
		t.Fatalf("set password: %v", err)
	}

	var prepared bool
	prepareDirectSocksRuntimeFunc = func(connectionTimeout, idleTimeout time.Duration) (*socksRuntime, error) {
		prepared = true
		if config.AppConfig.Socks.BindAddress != "0.0.0.0" {
			t.Fatalf("bind address not overridden: %q", config.AppConfig.Socks.BindAddress)
		}
		if config.AppConfig.Socks.Port != "2333" {
			t.Fatalf("port not overridden: %q", config.AppConfig.Socks.Port)
		}
		if config.AppConfig.Socks.Username != "alice" || config.AppConfig.Socks.Password != "secret" {
			t.Fatalf("credentials not overridden: %#v", config.AppConfig.Socks)
		}
		runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("not used")
		})
		runtime.SetTunnelUp(true)
		return runtime, nil
	}

	sentinel := errors.New("stop server")
	runSocksServerFunc = func(runtime *socksRuntime, idleTimeout time.Duration) error {
		if !runtime.IsTunnelUp() {
			t.Fatalf("expected direct socks runtime to stay up")
		}
		return sentinel
	}

	err := runSocksCmd(cmd, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("runSocksCmd() error = %v, want sentinel", err)
	}
	if !prepared {
		t.Fatalf("expected direct socks runtime to be prepared")
	}
}

func TestRunSocksCmdLoadsPublicConfigOnly(t *testing.T) {
	oldPrepare := prepareDirectSocksRuntimeFunc
	oldRunServer := runSocksServerFunc
	oldConfig := config.AppConfig
	oldLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		prepareDirectSocksRuntimeFunc = oldPrepare
		runSocksServerFunc = oldRunServer
		config.AppConfig = oldConfig
		config.ConfigLoaded = oldLoaded
	})

	dir := t.TempDir()
	configPath := dir + "/config.json"
	keyPath := dir + "/key.json"

	configJSON := `{
  "socks": {
    "bind_address": "127.0.0.1",
    "port": "1088",
    "username": "bob",
    "password": "pw",
    "dns": ["1.1.1.1"]
  },
  "logging": {
    "level": "debug",
    "format": "text"
  }
}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(`{"access_token":"should-not-load"}`), 0o600); err != nil {
		t.Fatalf("write key.json: %v", err)
	}

	config.AppConfig = config.Config{}
	config.ConfigLoaded = false

	cmd := newSocksCmdForTest()
	if err := cmd.Flags().Set("config", configPath); err != nil {
		t.Fatalf("set config flag: %v", err)
	}

	var prepared bool
	prepareDirectSocksRuntimeFunc = func(connectionTimeout, idleTimeout time.Duration) (*socksRuntime, error) {
		prepared = true
		if config.AppConfig.Socks.Port != "1088" {
			t.Fatalf("AppConfig.Socks.Port = %q, want %q", config.AppConfig.Socks.Port, "1088")
		}
		if config.AppConfig.Socks.Username != "bob" || config.AppConfig.Socks.Password != "pw" {
			t.Fatalf("unexpected credentials: %#v", config.AppConfig.Socks)
		}
		if config.AppConfig.AccessToken != "" {
			t.Fatalf("expected key material to stay empty, got %q", config.AppConfig.AccessToken)
		}
		runtime := newRuntimeForTest(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("not used")
		})
		runtime.SetTunnelUp(true)
		return runtime, nil
	}

	sentinel := errors.New("stop server")
	runSocksServerFunc = func(runtime *socksRuntime, idleTimeout time.Duration) error {
		return sentinel
	}

	err := runSocksCmd(cmd, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("runSocksCmd() error = %v, want sentinel", err)
	}
	if !prepared {
		t.Fatalf("expected public config to be loaded before preparing runtime")
	}
}

func TestPrepareDirectSocksRuntimeUsesSystemDialer(t *testing.T) {
	oldConfig := config.AppConfig
	oldLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		config.AppConfig = oldConfig
		config.ConfigLoaded = oldLoaded
	})

	config.AppConfig = config.Config{
		Socks:   config.GetDefaultSocksConfig(),
		Logging: config.GetDefaultLoggingConfig(),
	}
	config.ConfigLoaded = true

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	runtime, err := prepareDirectSocksRuntime(2*time.Second, 2*time.Second)
	if err != nil {
		t.Fatalf("prepareDirectSocksRuntime() error = %v", err)
	}
	if !runtime.IsTunnelUp() {
		t.Fatalf("expected direct socks runtime to be always up")
	}

	conn, err := runtime.DialContext(context.Background(), "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("DialContext() error = %v", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected listener to accept system dial")
	}
}

func TestPrepareDirectSocksRuntimeIgnoresBlockUDP443(t *testing.T) {
	oldConfig := config.AppConfig
	oldLoaded := config.ConfigLoaded
	t.Cleanup(func() {
		config.AppConfig = oldConfig
		config.ConfigLoaded = oldLoaded
	})

	config.AppConfig = config.Config{
		Socks:   config.GetDefaultSocksConfig(),
		Logging: config.GetDefaultLoggingConfig(),
	}
	config.AppConfig.Socks.BlockUDP443 = true
	config.ConfigLoaded = true

	runtime, err := prepareDirectSocksRuntime(2*time.Second, 2*time.Second)
	if err != nil {
		t.Fatalf("prepareDirectSocksRuntime() error = %v", err)
	}

	conn, err := runtime.DialContext(context.Background(), "udp", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("DialContext() should ignore block_udp_443 in socks mode, got %v", err)
	}
	_ = conn.Close()
}

func TestIgnoredSocksOnlySettingsIncludesTunnelSpecificOptions(t *testing.T) {
	cfg := config.Config{
		PrivateKey:     "masque-key",
		EndpointV4:     "162.159.0.1",
		EndpointPubKey: "peer",
		Socks: config.SocksConfig{
			BypassDomain: []string{"example.com"},
			ProxyTCPPort: []int{443},
			DNS:          []string{"9.9.9.9"},
			BlockUDP443:  true,
			RemoteDNS:    true,
			UseIPv6:      true,
		},
	}

	ignored := ignoredSocksOnlySettings(cfg)
	joined := strings.Join(ignored, ",")

	for _, needle := range []string{"private_key", "endpoint_v4", "endpoint_pub_key", "bypass_domain", "proxy_tcp_port", "dns", "block_udp_443", "remote_dns", "use_ipv6"} {
		if !strings.Contains(joined, needle) {
			t.Fatalf("ignored settings missing %q: %v", needle, ignored)
		}
	}
}
