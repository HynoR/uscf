package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

type tunnelTransport interface {
	Close() error
}

// tunnelCloseCauser is the optional capability a transport implements to expose
// the underlying QUIC connection's close cause. The tunnel layer type-asserts
// for it on disconnect so a masked "use of closed network connection" forwarding
// error can be replaced with the real QUIC reason (idle timeout, peer
// CONNECTION_CLOSE code, transport error). HTTP/2 transports don't implement it.
type tunnelCloseCauser interface {
	CloseCause() error
}

type closeFunc func() error

func (f closeFunc) Close() error {
	return f()
}

// http3TunnelTransport pairs the HTTP/3 transport with its QUIC connection so the
// connection's close cause is reachable after forwarding ends.
type http3TunnelTransport struct {
	*http3.Transport
	conn *quic.Conn
}

// CloseCause returns the QUIC connection's context cancellation cause (the real
// reason it closed), or nil while the connection is still alive.
func (t *http3TunnelTransport) CloseCause() error {
	if t == nil || t.conn == nil {
		return nil
	}
	return context.Cause(t.conn.Context())
}

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI (Server Name Indication).
// It also verifies the peer's public key against the provided public key.
//
// Parameters:
//   - privKey: *ecdsa.PrivateKey - The private key to use for TLS authentication.
//   - peerPubKey: *ecdsa.PublicKey - The endpoint's public key to pin to.
//   - cert: [][]byte - The certificate chain to use for TLS authentication.
//   - sni: string - The Server Name Indication (SNI) to use.
//
// Returns:
//   - *tls.Config: A TLS configuration for secure communication.
//   - error: An error if TLS setup fails.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// we pin to the endpoint public key
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
				// we only support ECDSA
				// TODO: don't hardcode cert type in the future
				// as backend can start using different cert types
				return x509.ErrUnsupportedAlgorithm
			}

			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
				// reason is incorrect, but the best I could figure
				// detail explains the actual reason

				//10 is NoValidChains, but we support go1.22 where it's not defined
				return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
			}

			return nil
		},
	}

	return tlsConfig, nil
}

// ConnectTunnel establishes a Connect-IP tunnel with the provided endpoint.
// It uses QUIC/HTTP3 by default and TCP/HTTP2 when useHTTP2 is true.
// Requires modified connect-ip-go for now to support Cloudflare's non RFC compliant implementation.
//
// Parameters:
//   - ctx: context.Context - The connection context.
//   - tlsConfig: *tls.Config - The TLS configuration for secure communication.
//   - quicConfig: *quic.Config - The QUIC configuration settings (HTTP/3 only).
//   - connectUri: string - The URI template for the Connect-IP request.
//   - endpoint: net.Addr - The selected remote endpoint.
//   - useHTTP2: bool - Connect over TCP+TLS+HTTP/2 instead of QUIC+HTTP/3.
//
// Returns:
//   - *net.UDPConn: The UDP connection used for the QUIC session (nil in HTTP/2 mode).
//   - tunnelTransport: The transport closer used by the session.
//   - *connectip.Conn: The Connect-IP connection instance.
//   - *http.Response: The response from the Connect-IP handshake.
//   - error: An error if the connection setup fails.
func ConnectTunnel(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, connectUri string, endpoint net.Addr, useHTTP2 bool) (*net.UDPConn, tunnelTransport, *connectip.Conn, *http.Response, error) {
	template := uritemplate.MustNew(connectUri)
	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	if useHTTP2 {
		tcpEndpoint, ok := endpoint.(*net.TCPAddr)
		if !ok || tcpEndpoint == nil {
			return nil, nil, nil, nil, errors.New("HTTP/2 mode requires a TCP endpoint")
		}

		http2Headers := additionalHeaders.Clone()
		http2Headers.Set("cf-connect-proto", "cf-connect-ip")
		http2Headers.Set("pq-enabled", "false")

		client, closer, err := newHTTP2Client(tlsConfig, tcpEndpoint, connectUri)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to create HTTP/2 client: %w", err)
		}

		ipConn, rsp, err := connectip.DialH2(ctx, client, template, http2Headers)
		if err != nil {
			_ = closer.Close()
			if strings.Contains(err.Error(), "tls: access denied") {
				return nil, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
			}
			return nil, nil, nil, nil, fmt.Errorf("failed to dial connect-ip over HTTP/2: %w", err)
		}

		return nil, closer, ipConn, rsp, nil
	}

	udpEndpoint, ok := endpoint.(*net.UDPAddr)
	if !ok || udpEndpoint == nil {
		return nil, nil, nil, nil, errors.New("HTTP/3 mode requires a UDP endpoint")
	}

	// Cloudflare's edge occasionally aborts the very first connect-ip response
	// read with a QUIC PROTOCOL_VIOLATION right after the handshake. Retry the
	// HTTP/3 connect once before giving up. Ported from usque 21d9243.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		udpConn, tr, ipConn, rsp, err := connectTunnelHTTP3(ctx, tlsConfig, quicConfig, template, additionalHeaders, udpEndpoint)
		if err == nil {
			return udpConn, tr, ipConn, rsp, nil
		}
		if strings.Contains(err.Error(), "tls: access denied") {
			return nil, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		lastErr = err
		if !isRetryableHTTP3ConnectFailure(err) {
			break
		}
	}
	return nil, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %w", lastErr)
}

// connectTunnelHTTP3 performs a single QUIC+HTTP/3 connect-ip dial. It owns the
// UDP socket it creates and closes it on every error path, so a failed attempt
// never leaks a socket — the caller's cleanup only runs on the success path.
func connectTunnelHTTP3(ctx context.Context, tlsConfig *tls.Config, quicConfig *quic.Config, template *uritemplate.Template, additionalHeaders http.Header, udpEndpoint *net.UDPAddr) (*net.UDPConn, tunnelTransport, *connectip.Conn, *http.Response, error) {
	var udpConn *net.UDPConn
	var err error
	if udpEndpoint.IP.To4() == nil {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: 0,
		})
	} else {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: 0,
		})
	}
	if err != nil {
		return nil, nil, nil, nil, err
	}

	conn, err := quic.Dial(
		ctx,
		udpConn,
		udpEndpoint,
		tlsConfig,
		quicConfig,
	)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, nil, nil, err
	}

	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// official client still sends this out as well, even though
			// it's deprecated, see https://datatracker.ietf.org/doc/draft-ietf-masque-h3-datagram/00/
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			// https://github.com/cloudflare/quiche/blob/7c66757dbc55b8d0c3653d4b345c6785a181f0b7/quiche/src/h3/frame.rs#L46
			0x276: 1,
		},
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(conn)

	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		_ = tr.Close()
		_ = conn.CloseWithError(0, "connect-ip dial failed")
		_ = udpConn.Close()
		return nil, nil, nil, nil, err
	}

	// Return a transport that also carries the QUIC connection, so the tunnel
	// layer can read its close cause on disconnect (see http3TunnelTransport).
	return udpConn, &http3TunnelTransport{Transport: tr, conn: conn}, ipConn, rsp, nil
}

// isRetryableHTTP3ConnectFailure reports whether a connect-ip dial failed with a
// transient QUIC PROTOCOL_VIOLATION while reading the first response, which is
// worth one immediate retry.
func isRetryableHTTP3ConnectFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "failed to read response") &&
		strings.Contains(msg, "PROTOCOL_VIOLATION")
}

func newHTTP2Client(baseTLSConfig *tls.Config, endpoint *net.TCPAddr, connectURI string) (*http.Client, tunnelTransport, error) {
	if endpoint == nil {
		return nil, nil, errors.New("missing HTTP/2 endpoint")
	}

	parsedURI, err := url.Parse(connectURI)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse connect URI: %w", err)
	}

	tlsConfig := baseTLSConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}

	originAuthority := authorityWithDefaultPort(parsedURI, "443")
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:              http.ProxyFromEnvironment,
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == originAuthority {
				addr = endpoint.String()
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, nil, fmt.Errorf("failed to configure HTTP/2 transport: %w", err)
	}

	return &http.Client{Transport: transport}, closeFunc(func() error {
		transport.CloseIdleConnections()
		return nil
	}), nil
}

func authorityWithDefaultPort(u *url.URL, defaultPort string) string {
	if u == nil {
		return ""
	}

	host := u.Hostname()
	if host == "" {
		return u.Host
	}

	port := u.Port()
	if port == "" {
		port = defaultPort
	}

	return net.JoinHostPort(host, port)
}
