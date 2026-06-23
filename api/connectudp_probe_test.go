package api

// Live probe: does Cloudflare's MASQUE *proxy* endpoint (the L4 SNI) speak
// RFC 9298 CONNECT-UDP? Gated behind RUN_CF_UDP_PROBE so it never runs in CI.
//
//	RUN_CF_UDP_PROBE=1 go test ./api -run TestProbeCloudflareConnectUDP -v -count=1
//
// It registers a throwaway free WARP account, enrolls a MASQUE key, dials the
// proxy endpoint with QUIC datagrams enabled, and tries to open a connect-udp
// request stream to 1.1.1.1:53. The HTTP status alone answers the question; if
// it is 2xx we additionally send a real DNS query as an HTTP datagram and wait
// for a reply.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/HynoR/uscf/internal"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestProbeCloudflareConnectUDP(t *testing.T) {
	if os.Getenv("RUN_CF_UDP_PROBE") == "" {
		t.Skip("set RUN_CF_UDP_PROBE=1 to run the live Cloudflare connect-udp probe")
	}

	// 1. Fresh MASQUE key + free WARP enrollment.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
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
	endpoint := &net.UDPAddr{IP: net.ParseIP(host), Port: 443}
	t.Logf("enrolled: endpoint=%s account=%s", endpoint, updated.Config.Interface.Addresses.V4)

	// 2. Parse the edge public key (PEM) and build the pinned TLS config.
	block, _ := pem.Decode([]byte(peer.PublicKey))
	if block == nil {
		t.Fatalf("endpoint pub key is not PEM: %q", peer.PublicKey)
	}
	parsedPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse edge pub: %v", err)
	}
	peerPub, ok := parsedPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("edge pub is not ECDSA: %T", parsedPub)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	tlsConfig, err := PrepareTlsConfig(privKey, peerPub, cert, internal.L4ConnectSNI)
	if err != nil {
		t.Fatalf("tls config: %v", err)
	}

	// 3. Dial the proxy endpoint with QUIC datagrams ENABLED (required for
	//    RFC 9298). The current L4 mode disables them — this is the probe's whole
	//    point.
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer udpConn.Close()

	qconf := &quic.Config{
		EnableDatagrams:   true,
		InitialPacketSize: 1242,
		KeepAlivePeriod:   20 * time.Second,
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	qconn, err := quic.Dial(dialCtx, udpConn, endpoint, tlsConfig, qconf)
	if err != nil {
		t.Fatalf("quic dial proxy endpoint: %v", err)
	}
	defer qconn.CloseWithError(0, "")

	qconn.CloseWithError(0, "probe-settings-only")
	_ = udpConn.Close()

	// Each request shape gets its own fresh QUIC connection, because a
	// PROTOCOL_VIOLATION tears down the whole connection (not just the stream).
	// enableDatagrams is threaded through because it is the decisive variable:
	// the production L4 path runs with datagrams DISABLED.
	dialFresh := func(enableDatagrams bool) (*http3.ClientConn, func(), error) {
		uc, derr := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
		if derr != nil {
			return nil, nil, derr
		}
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer dcancel()
		dialConf := &quic.Config{
			EnableDatagrams:   enableDatagrams,
			InitialPacketSize: 1242,
			KeepAlivePeriod:   20 * time.Second,
		}
		qc, derr := quic.Dial(dctx, uc, endpoint, tlsConfig, dialConf)
		if derr != nil {
			_ = uc.Close()
			return nil, nil, derr
		}
		conn := (&http3.Transport{EnableDatagrams: enableDatagrams}).NewClientConn(qc)
		select {
		case <-conn.ReceivedSettings():
		case <-time.After(10 * time.Second):
		}
		cleanup := func() { qc.CloseWithError(0, ""); _ = uc.Close() }
		return conn, cleanup, nil
	}

	sendConnect := func(label string, enableDatagrams bool, req *http.Request) {
		conn, cleanup, derr := dialFresh(enableDatagrams)
		if derr != nil {
			t.Logf("[%s] dial failed: %v", label, derr)
			return
		}
		defer cleanup()
		rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer rcancel()
		rstr, derr := conn.OpenRequestStream(rctx)
		if derr != nil {
			t.Logf("[%s] open stream: %v", label, derr)
			return
		}
		req = req.WithContext(rctx)
		if derr := rstr.SendRequestHeader(req); derr != nil {
			t.Logf("[%s] send header: %v", label, derr)
			return
		}
		resp, derr := rstr.ReadResponse()
		if derr != nil {
			t.Logf("[%s] => REJECTED at protocol level: %v", label, derr)
			return
		}
		t.Logf("[%s] => HTTP status %d", label, resp.StatusCode)
	}

	mkURL := func(raw string) *url.URL {
		u, perr := url.Parse(raw)
		if perr != nil {
			t.Fatalf("parse url %q: %v", raw, perr)
		}
		return u
	}

	// (a0) CONTROL, datagrams DISABLED: plain TCP CONNECT built EXACTLY like
	//      api.L4Proxy.dial. This replicates the production L4 path and must
	//      return 2xx — proving the enrollment/conn/request plumbing is sound.
	ctlReq0, _ := http.NewRequestWithContext(context.Background(), http.MethodConnect, "https://1.1.1.1:443", nil)
	ctlReq0.Host = "1.1.1.1:443"
	sendConnect("control TCP CONNECT (datagrams OFF)", false, ctlReq0)

	// (a1) Same plain TCP CONNECT but datagrams ENABLED — isolates whether merely
	//      negotiating datagram support (a prerequisite for connect-udp) breaks
	//      CF's TCP CONNECT path on the proxy endpoint.
	ctlReq1, _ := http.NewRequestWithContext(context.Background(), http.MethodConnect, "https://1.1.1.1:443", nil)
	ctlReq1.Host = "1.1.1.1:443"
	sendConnect("control TCP CONNECT (datagrams ON)", true, ctlReq1)

	// (b) RFC 9298 connect-udp, well-known URI template path form (datagrams ON).
	//     Built exactly like connectip.Dial (which returns 2xx for connect-ip on
	//     the L3 endpoint), differing only in :protocol and the udp template.
	for i := 0; i < 3; i++ {
		udpTmpl := mkURL("https://" + internal.L4ConnectSNI + "/.well-known/masque/udp/1.1.1.1/" + strconv.Itoa(53) + "/")
		sendConnect("connect-udp RFC9298 path 1.1.1.1/53 #"+strconv.Itoa(i+1), true, &http.Request{
			Method: http.MethodConnect,
			Proto:  "connect-udp",
			Host:   udpTmpl.Host,
			URL:    udpTmpl,
			Header: http.Header{http3.CapsuleProtocolHeader: []string{"?1"}},
		})
	}

	// (c) Older masque draft authority form: :protocol=connect-udp with the target
	//     as :authority and path "/" (datagrams ON).
	udpAuth := mkURL("https://1.1.1.1:53")
	sendConnect("connect-udp authority 1.1.1.1:53", true, &http.Request{
		Method: http.MethodConnect,
		Proto:  "connect-udp",
		Host:   "1.1.1.1:53",
		URL:    udpAuth,
		Header: http.Header{http3.CapsuleProtocolHeader: []string{"?1"}},
	})
}
