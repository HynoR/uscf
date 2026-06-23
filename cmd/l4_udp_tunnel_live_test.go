package cmd

// Live end-to-end test for L4 "mix" mode (l4_udp=tunnel). Gated behind
// RUN_CF_UDP_PROBE.
//
//	RUN_CF_UDP_PROBE=1 go test ./cmd -run TestL4TunnelUDPLive -v -count=1
//
// It registers a throwaway free WARP account, stands up the real L4 SOCKS runtime
// (TCP leg) plus the parallel lazy L3 connect-ip tunnel (UDP leg), warms the UDP
// leg, then drives a SOCKS5 UDP ASSOCIATE that round-trips a DNS query to
// 1.1.1.1:53. Unlike "direct" mode, the datagram is tunneled through WARP, so a
// reply proves the UDP-over-L3 path is wired end to end: ASSOCIATE → dialWithTarget
// → l3UDPTunnel.DialUDP → netstack → connect-ip → CF → DNS → back.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
)

func TestL4TunnelUDPLive(t *testing.T) {
	if os.Getenv("RUN_CF_UDP_PROBE") == "" {
		t.Skip("set RUN_CF_UDP_PROBE=1 to run the live L4 mix-mode (tunnel UDP) test")
	}

	// 1. Register + enroll a throwaway free WARP account.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	account, err := api.Register("PC", "en-US", "", true)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	updated, apiErr, err := api.EnrollKey(account, pubDER, "PC")
	if err != nil {
		t.Fatalf("enroll: %v (api: %v)", err, apiErr)
	}
	if len(updated.Config.Peers) == 0 {
		t.Fatalf("enroll: no peers")
	}
	peer := updated.Config.Peers[0]
	host := peer.Endpoint.V4
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}

	// 2. Populate config.AppConfig exactly as a saved enrollment would, including
	//    the WARP-assigned interface addresses the connect-ip leg needs.
	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	socks := config.GetDefaultSocksConfig()
	socks.L4 = true
	socks.L4UDP = config.L4UDPTunnel
	socks.BlockUDP443 = false
	socks, err = config.NormalizeSocksConfig(socks)
	if err != nil {
		t.Fatalf("normalize socks: %v", err)
	}
	config.AppConfig.PrivateKey = base64.StdEncoding.EncodeToString(privDER)
	config.AppConfig.EndpointV4 = host
	config.AppConfig.EndpointPubKey = peer.PublicKey
	config.AppConfig.IPv4 = updated.Config.Interface.Addresses.V4
	config.AppConfig.IPv6 = updated.Config.Interface.Addresses.V6
	config.AppConfig.Socks = socks

	// Verbose + debug logging so the mix-mode UDP lines are visible.
	config.AppConfig.Logging.SocksVerbose = true
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	// 3. Build the L4 (TCP) runtime and the parallel L3 (UDP) tunnel in-process.
	tlsConfig, err := prepareL4TlsConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}
	endpoint, selector, err := selectL4Endpoint()
	if err != nil {
		t.Fatalf("select endpoint: %v", err)
	}
	l4Proxy, err := api.NewL4Proxy(api.L4ProxyConfig{
		TLSConfig:        tlsConfig,
		QUICConfig:       l4QUICConfig(socks.KeepalivePeriod.Duration(), socks.InitialPacketSize),
		Endpoint:         endpoint,
		EndpointSelector: selector,
		ConnectTimeout:   10 * time.Second,
	})
	if err != nil {
		t.Fatalf("new l4 proxy: %v", err)
	}
	defer l4Proxy.Close()

	udpTunnel, cleanup, err := startL3UDPTunnel(nil, 10*time.Second, 30*time.Second)
	if err != nil {
		t.Fatalf("start l3 udp tunnel: %v", err)
	}
	defer cleanup()

	runtime, _, err := prepareL4SocksRuntime(l4Proxy, udpTunnel, 10*time.Second, 30*time.Second)
	if err != nil {
		t.Fatalf("prepare runtime: %v", err)
	}
	runtime.SetTunnelUp(true)
	srv := runtime.CurrentServer()
	if srv == nil {
		t.Fatalf("nil socks server")
	}

	// 4. Warm the lazy UDP leg: the first dial triggers the connect-ip handshake
	//    (and is dropped). Poll until it reports up so the round-trip below lands on
	//    a live tunnel rather than getting dropped + retried.
	_, _ = udpTunnel.DialUDP(context.Background(), "1.1.1.1:53")
	deadline := time.Now().Add(25 * time.Second)
	for !udpTunnel.up.Load() {
		if time.Now().After(deadline) {
			t.Fatal("L3 UDP tunnel did not come up within 25s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("L3 UDP tunnel is up; driving SOCKS5 UDP ASSOCIATE")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() { _ = srv.ServeConn(conn) }()
		}
	}()

	// 5. Drive a SOCKS5 UDP ASSOCIATE and round-trip a DNS query to 1.1.1.1:53
	//    through the tunnel. The leg has keepalive disabled and self-evicts after
	//    ~30s idle, so retry with a re-warm: if it slept between warm-up and the
	//    datagram, the first attempt drops, the re-warm wakes it, and the next
	//    attempt lands on a live tunnel.
	var reply []byte
	var rtErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if !udpTunnel.up.Load() {
			_, _ = udpTunnel.DialUDP(context.Background(), "1.1.1.1:53")
			warmDeadline := time.Now().Add(25 * time.Second)
			for !udpTunnel.up.Load() {
				if time.Now().After(warmDeadline) {
					t.Fatal("L3 UDP tunnel did not come back up within 25s")
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		reply, rtErr = socks5UDPRoundTrip(ln.Addr().String(), "1.1.1.1", 53, dnsQueryCloudflareA())
		if rtErr == nil {
			break
		}
		t.Logf("attempt %d: UDP round-trip failed (%v); re-warming and retrying", attempt, rtErr)
	}
	if rtErr != nil {
		t.Fatalf("socks5 udp round-trip failed after retries: %v", rtErr)
	}
	if len(reply) < 12 {
		t.Fatalf("short DNS reply: %d bytes", len(reply))
	}
	if reply[0] != 0x12 || reply[1] != 0x34 {
		t.Fatalf("DNS reply ID mismatch: %x %x", reply[0], reply[1])
	}
	if reply[2]&0x80 == 0 {
		t.Fatalf("DNS reply QR bit not set")
	}
	ancount := binary.BigEndian.Uint16(reply[6:8])
	t.Logf("VERDICT: L4 mix-mode tunnel-UDP works — DNS reply %d bytes, ANCOUNT=%d", len(reply), ancount)
}
