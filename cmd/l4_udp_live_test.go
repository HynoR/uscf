package cmd

// Live end-to-end test for L4 "direct" UDP. Gated behind RUN_CF_UDP_PROBE.
//
//	RUN_CF_UDP_PROBE=1 go test ./cmd -run TestL4DirectUDPLive -v -count=1
//
// It registers a throwaway free WARP account, stands up the real L4 SOCKS
// runtime in-process with l4_udp=direct, and drives a SOCKS5 UDP ASSOCIATE that
// sends a DNS query to 1.1.1.1:53. A direct-mode datagram bypasses WARP, so the
// reply proves the ASSOCIATE path is wired (negotiation, relay socket, direct
// dial, response framing) without depending on the fake-IP resolver.

import (
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

func TestL4DirectUDPLive(t *testing.T) {
	if os.Getenv("RUN_CF_UDP_PROBE") == "" {
		t.Skip("set RUN_CF_UDP_PROBE=1 to run the live L4 direct-UDP test")
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

	// 2. Populate config.AppConfig exactly as a saved enrollment would.
	privDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("marshal priv: %v", err)
	}
	socks := config.GetDefaultSocksConfig()
	socks.L4 = true
	socks.L4UDP = config.L4UDPDirect
	socks.BlockUDP443 = false
	socks, err = config.NormalizeSocksConfig(socks)
	if err != nil {
		t.Fatalf("normalize socks: %v", err)
	}
	config.AppConfig.PrivateKey = base64.StdEncoding.EncodeToString(privDER)
	config.AppConfig.EndpointV4 = host
	config.AppConfig.EndpointPubKey = peer.PublicKey
	config.AppConfig.Socks = socks

	// Enable verbose + debug logging so the UDP proxying lines are visible: this
	// exercises the success-logging path (ASSOCIATE established / flow established
	// / reply received).
	config.AppConfig.Logging.SocksVerbose = true
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))

	// 3. Build the real L4 runtime in-process (same code paths the command uses).
	tlsConfig, err := prepareL4TlsConfig()
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}
	endpoint, err := selectL4Endpoint()
	if err != nil {
		t.Fatalf("select endpoint: %v", err)
	}
	l4Pool, err := api.NewL4Pool(api.L4ProxyConfig{
		TLSConfig:      tlsConfig,
		QUICConfig:     l4QUICConfig(socks.KeepalivePeriod.Duration(), socks.InitialPacketSize),
		Endpoint:       endpoint,
		ConnectTimeout: 10 * time.Second,
	}, 1)
	if err != nil {
		t.Fatalf("new l4 pool: %v", err)
	}
	defer l4Pool.Close()

	runtime, _, err := prepareL4SocksRuntime(l4Pool, nil, 10*time.Second, 30*time.Second)
	if err != nil {
		t.Fatalf("prepare runtime: %v", err)
	}
	runtime.SetTunnelUp(true)
	srv := runtime.CurrentServer()
	if srv == nil {
		t.Fatalf("nil socks server")
	}

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

	// 4. Drive a SOCKS5 UDP ASSOCIATE and round-trip a DNS query to 1.1.1.1:53.
	reply, err := socks5UDPRoundTrip(ln.Addr().String(), "1.1.1.1", 53, dnsQueryCloudflareA())
	if err != nil {
		t.Fatalf("socks5 udp round-trip: %v", err)
	}
	if len(reply) < 12 {
		t.Fatalf("short DNS reply: %d bytes", len(reply))
	}
	// DNS response must echo our query ID (0x1234) and have QR=1.
	if reply[0] != 0x12 || reply[1] != 0x34 {
		t.Fatalf("DNS reply ID mismatch: %x %x", reply[0], reply[1])
	}
	if reply[2]&0x80 == 0 {
		t.Fatalf("DNS reply QR bit not set")
	}
	ancount := binary.BigEndian.Uint16(reply[6:8])
	t.Logf("VERDICT: L4 direct-UDP works — DNS reply %d bytes, ANCOUNT=%d", len(reply), ancount)
}

func dnsQueryCloudflareA() []byte {
	return []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // flags: RD
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x0a, 'c', 'l', 'o', 'u', 'd', 'f', 'l', 'a', 'r', 'e',
		0x03, 'c', 'o', 'm',
		0x00,
		0x00, 0x01, // QTYPE A
		0x00, 0x01, // QCLASS IN
	}
}

// socks5UDPRoundTrip negotiates SOCKS5 (no auth), issues a UDP ASSOCIATE, then
// sends one datagram to dstHost:dstPort through the returned relay and returns
// the payload of the first reply datagram (SOCKS header stripped).
func socks5UDPRoundTrip(proxyAddr, dstHost string, dstPort int, payload []byte) ([]byte, error) {
	ctrl, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(10 * time.Second))

	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth).
	if _, err := ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err := readFull(ctrl, resp); err != nil {
		return nil, err
	}

	// UDP ASSOCIATE: VER=5, CMD=3, RSV=0, ATYP=1, 0.0.0.0:0 (zero source).
	if _, err := ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return nil, err
	}
	head := make([]byte, 4)
	if _, err := readFull(ctrl, head); err != nil {
		return nil, err
	}
	var bndIP net.IP
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := readFull(ctrl, b); err != nil {
			return nil, err
		}
		bndIP = net.IP(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := readFull(ctrl, b); err != nil {
			return nil, err
		}
		bndIP = net.IP(b)
	default:
		return nil, errReply(head)
	}
	portBuf := make([]byte, 2)
	if _, err := readFull(ctrl, portBuf); err != nil {
		return nil, err
	}
	relayPort := int(binary.BigEndian.Uint16(portBuf))
	if bndIP.IsUnspecified() {
		bndIP = net.ParseIP("127.0.0.1")
	}

	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: bndIP, Port: relayPort})
	if err != nil {
		return nil, err
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(8 * time.Second))

	// SOCKS UDP request: RSV(2)=0, FRAG=0, ATYP=1, DST.ADDR(4), DST.PORT(2), DATA.
	dgram := []byte{0x00, 0x00, 0x00, 0x01}
	dgram = append(dgram, net.ParseIP(dstHost).To4()...)
	dgram = append(dgram, byte(dstPort>>8), byte(dstPort))
	dgram = append(dgram, payload...)
	if _, err := uc.Write(dgram); err != nil {
		return nil, err
	}

	buf := make([]byte, 65535)
	n, err := uc.Read(buf)
	if err != nil {
		return nil, err
	}
	// Strip the SOCKS UDP header (IPv4: 2 RSV + 1 FRAG + 1 ATYP + 4 ADDR + 2 PORT).
	const ipv4HeaderLen = 10
	if n <= ipv4HeaderLen {
		return nil, errShort(n)
	}
	return buf[ipv4HeaderLen:n], nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		if n > 0 {
			got += n
		}
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

type socksError string

func (e socksError) Error() string { return string(e) }

func errReply(head []byte) error { return socksError("unexpected SOCKS reply ATYP/REP") }
func errShort(n int) error       { return socksError("reply datagram too short") }
