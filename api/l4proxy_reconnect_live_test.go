package api

// Live test for L4 shared-connection recovery. Gated behind RUN_CF_UDP_PROBE.
//
//	RUN_CF_UDP_PROBE=1 go test ./api -run TestL4ProxyRecoversAfterConnDeath -v -count=1
//
// Reproduces the reported failure: after the shared QUIC connection dies, the cached
// (dead) connection must not linger. In the mihomo model the recovery is lazy — the
// next dial that fails to open a stream tears the dead connection down (closeConn) and
// the dial after that rebuilds. This asserts that killing the shared connection leads
// to a fresh connection (reconnect counter bumps) and dialing succeeds again quickly.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"testing"
	"time"

	"github.com/HynoR/uscf/internal"
	"github.com/quic-go/quic-go"
)

func TestL4ProxyRecoversAfterConnDeath(t *testing.T) {
	if os.Getenv("RUN_CF_UDP_PROBE") == "" {
		t.Skip("set RUN_CF_UDP_PROBE=1 to run the live L4 reconnect test")
	}

	tlsConfig, endpoint := enrollFreeWARPForL4(t)
	p, err := NewL4Proxy(L4ProxyConfig{
		TLSConfig:      tlsConfig,
		Endpoint:       endpoint,
		ConnectTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewL4Proxy: %v", err)
	}
	defer p.Close()

	// 1. First dial establishes the shared connection. 1.1.1.1:443 is a literal IP
	//    (avoids the fake-IP DNS env) and returns an HTTP response over the tunnel.
	ctx := context.Background()
	conn1, err := p.DialContext(ctx, "1.1.1.1:443")
	if err != nil {
		t.Fatalf("first dial failed: %v", err)
	}
	_ = conn1.Close()

	p.mu.Lock()
	deadQUIC := p.quicConn
	p.mu.Unlock()
	if deadQUIC == nil {
		t.Fatalf("expected a cached shared connection after first dial")
	}
	if _, rc := p.Stats(); rc != 0 {
		t.Fatalf("reconnects = %d before death, want 0", rc)
	}

	// 2. Simulate the connection dying (CF idle eviction / path failure).
	_ = deadQUIC.CloseWithError(quic.ApplicationErrorCode(0), "simulated death")

	// 3. Subsequent dials must rebuild and succeed quickly — NOT hang on the dead
	//    connection. The first post-death dial may fail (it is the one that observes the
	//    dead connection via OpenRequestStream and tears it down); the next rebuilds.
	start := time.Now()
	deadline := time.Now().Add(20 * time.Second)
	var conn2 net.Conn
	for {
		dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		conn2, err = p.DialContext(dialCtx, "1.1.1.1:443")
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial after conn death never recovered: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	elapsed := time.Since(start)
	_ = conn2.Close()

	p.mu.Lock()
	rebuilt := p.quicConn
	p.mu.Unlock()
	if rebuilt == nil || rebuilt == deadQUIC {
		t.Fatalf("expected a fresh shared connection after recovery")
	}
	if _, rc := p.Stats(); rc < 1 {
		t.Fatalf("reconnects = %d after recovery, want >= 1 (closeConn should have fired)", rc)
	}
	t.Logf("VERDICT: L4 recovered after conn death in %v; reconnects=%d", elapsed, func() uint64 { _, rc := p.Stats(); return rc }())
}

// enrollFreeWARPForL4 registers a throwaway free WARP account and returns a TLS config
// + endpoint pinned to the L4 (MASQUE proxy) SNI.
func enrollFreeWARPForL4(t *testing.T) (*tls.Config, *net.UDPAddr) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	account, err := Register("PC", "en-US", "", true)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	updated, apiErr, err := EnrollKey(account, pubDER, "PC")
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
	block, _ := pem.Decode([]byte(peer.PublicKey))
	if block == nil {
		t.Fatalf("endpoint pub key is not PEM")
	}
	parsedPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse edge pub: %v", err)
	}
	peerPub, ok := parsedPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("edge pub is not ECDSA")
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	tlsConfig, err := PrepareTlsConfig(privKey, peerPub, cert, internal.L4ConnectSNI)
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}
	return tlsConfig, &net.UDPAddr{IP: net.ParseIP(host), Port: 443}
}
