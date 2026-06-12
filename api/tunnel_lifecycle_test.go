package api

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type noopTunnelDevice struct{}

func (noopTunnelDevice) ReadPacket(buf []byte) (int, error) {
	return 0, errors.New("not implemented")
}

func (noopTunnelDevice) WritePacket(pkt []byte) error {
	return errors.New("not implemented")
}

func TestHandleConnectionOnDisconnectedAfterEstablished(t *testing.T) {
	oldConnectTunnelFunc := connectTunnelFunc
	oldHandleForwardingFn := handleForwardingFn
	defer func() {
		connectTunnelFunc = oldConnectTunnelFunc
		handleForwardingFn = oldHandleForwardingFn
	}()

	connectTunnelFunc = func(
		ctx context.Context,
		tlsConfig *tls.Config,
		quicConfig *quic.Config,
		connectURI string,
		endpoint *net.UDPAddr,
	) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
		return nil, nil, nil, &http.Response{StatusCode: http.StatusOK, Status: "200 OK"}, nil
	}

	forwardErr := errors.New("forwarding failed")
	handleForwardingFn = func(ctx context.Context, forwarding *forwardingSupervisor, ipConn *connectip.Conn) error {
		return forwardErr
	}

	var connectedCount int
	var disconnectedCount int
	var disconnectedErr error

	cfg := ConnectionConfig{
		TLSConfig:         &tls.Config{},
		KeepAlivePeriod:   time.Second,
		InitialPacketSize: 1242,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443},
		MTU:               1280,
		OnConnected: func() {
			connectedCount++
		},
		OnDisconnected: func(err error) {
			disconnectedCount++
			disconnectedErr = err
		},
	}

	attempt, err := handleConnection(context.Background(), cfg, noopTunnelDevice{}, 0)
	if !errors.Is(err, forwardErr) {
		t.Fatalf("expected forwarding error, got: %v", err)
	}
	if attempt != 0 {
		t.Fatalf("expected reconnect attempt reset to 0 after established connection, got: %d", attempt)
	}
	if connectedCount != 1 {
		t.Fatalf("expected OnConnected to be called once, got: %d", connectedCount)
	}
	if disconnectedCount != 1 {
		t.Fatalf("expected OnDisconnected to be called once, got: %d", disconnectedCount)
	}
	if !errors.Is(disconnectedErr, forwardErr) {
		t.Fatalf("expected OnDisconnected to receive forwarding error, got: %v", disconnectedErr)
	}
}

func TestHandleConnectionNoOnDisconnectedBeforeEstablished(t *testing.T) {
	oldConnectTunnelFunc := connectTunnelFunc
	oldHandleForwardingFn := handleForwardingFn
	defer func() {
		connectTunnelFunc = oldConnectTunnelFunc
		handleForwardingFn = oldHandleForwardingFn
	}()

	connectTunnelFunc = func(
		ctx context.Context,
		tlsConfig *tls.Config,
		quicConfig *quic.Config,
		connectURI string,
		endpoint *net.UDPAddr,
	) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
		return nil, nil, nil, &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable"}, nil
	}

	disconnectedCount := 0
	cfg := ConnectionConfig{
		TLSConfig:         &tls.Config{},
		KeepAlivePeriod:   time.Second,
		InitialPacketSize: 1242,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443},
		MTU:               1280,
		OnDisconnected: func(err error) {
			disconnectedCount++
		},
	}

	attempt, err := handleConnection(context.Background(), cfg, noopTunnelDevice{}, 0)
	if err == nil {
		t.Fatalf("expected handshake failure")
	}
	if !strings.Contains(err.Error(), "tunnel connection failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempt != 1 {
		t.Fatalf("expected reconnect attempt to increment to 1, got: %d", attempt)
	}
	if disconnectedCount != 0 {
		t.Fatalf("expected OnDisconnected not to be called before establishment, got: %d", disconnectedCount)
	}
}

func TestHandleConnectionUsesEndpointSelectorPerAttempt(t *testing.T) {
	oldConnectTunnelFunc := connectTunnelFunc
	oldHandleForwardingFn := handleForwardingFn
	defer func() {
		connectTunnelFunc = oldConnectTunnelFunc
		handleForwardingFn = oldHandleForwardingFn
	}()

	var dialed []string
	connectTunnelFunc = func(
		ctx context.Context,
		tlsConfig *tls.Config,
		quicConfig *quic.Config,
		connectURI string,
		endpoint *net.UDPAddr,
	) (*net.UDPConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
		dialed = append(dialed, endpoint.IP.String())
		return nil, nil, nil, &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable"}, nil
	}

	endpoints := []*net.UDPAddr{
		{IP: net.ParseIP("1.1.1.1"), Port: 443},
		{IP: net.ParseIP("1.1.1.2"), Port: 443},
	}
	selectorCalls := 0
	cfg := ConnectionConfig{
		TLSConfig:         &tls.Config{},
		KeepAlivePeriod:   time.Second,
		InitialPacketSize: 1242,
		Endpoint:          &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 443},
		EndpointSelector: func() *net.UDPAddr {
			picked := endpoints[selectorCalls%len(endpoints)]
			selectorCalls++
			return picked
		},
		MTU:              1280,
	}

	_, _ = handleConnection(context.Background(), cfg, noopTunnelDevice{}, 0)
	_, _ = handleConnection(context.Background(), cfg, noopTunnelDevice{}, 1)

	if selectorCalls != 2 {
		t.Fatalf("expected selector to be called per attempt, got %d", selectorCalls)
	}
	if len(dialed) != 2 {
		t.Fatalf("expected two dial attempts, got %d", len(dialed))
	}
	if dialed[0] != "1.1.1.1" || dialed[1] != "1.1.1.2" {
		t.Fatalf("unexpected selected endpoints: %#v", dialed)
	}
}
