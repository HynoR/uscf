package api

// Live test for L4 shared-connection recovery. Gated behind RUN_CF_UDP_PROBE.
//
//	RUN_CF_UDP_PROBE=1 go test ./api -run TestL4ProxyRecoversAfterConnDeath -v -count=1
//
// Reproduces the reported failure: after the shared QUIC connection dies, the
// cached (dead) connection used to linger — every new dial would block in
// ReadResponse until timeout. This asserts that killing the shared connection
// invalidates the cache (watchClientConn) and the next dial rebuilds quickly.

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

	p.connMu.Lock()
	dead := p.clients[0]
	p.connMu.Unlock()
	if dead == nil || dead.quicConn == nil {
		t.Fatalf("expected a cached shared connection after first dial")
	}

	// 2. Simulate the connection dying (CF idle eviction / path failure).
	_ = dead.quicConn.CloseWithError(quic.ApplicationErrorCode(0), "simulated death")

	// 3. watchClientConn must evict the dead connection from the cache promptly.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p.connMu.Lock()
		current := p.clients[0]
		p.connMu.Unlock()
		if current != dead {
			break // evicted (nil) or already replaced
		}
		if time.Now().After(deadline) {
			t.Fatal("watchClientConn did not invalidate the dead connection within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 4. The next dial must rebuild and succeed quickly — NOT hang on the dead
	//    connection. Bound it well under the old failure window.
	start := time.Now()
	dialCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn2, err := p.DialContext(dialCtx, "1.1.1.1:443")
	if err != nil {
		t.Fatalf("dial after conn death failed (did not recover): %v", err)
	}
	elapsed := time.Since(start)
	_ = conn2.Close()

	p.connMu.Lock()
	rebuilt := p.clients[0]
	p.connMu.Unlock()
	if rebuilt == nil || rebuilt == dead {
		t.Fatalf("expected a fresh shared connection after recovery")
	}
	t.Logf("VERDICT: L4 recovered after conn death; rebuild dial took %v", elapsed)
}

// enrollFreeWARPForL4 registers a throwaway free WARP account and returns a TLS
// config + endpoint pinned to the L4 (MASQUE proxy) SNI.
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
