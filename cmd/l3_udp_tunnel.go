package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HynoR/uscf/api"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal/netstack"
	"github.com/HynoR/uscf/models"
	"github.com/spf13/cobra"
)

// l3UDPTunnel is the UDP-only leg of "mix" mode (socks.l4_udp=tunnel): a parallel
// connect-ip (L3 / gVisor netstack) tunnel that carries SOCKS UDP ASSOCIATE
// datagrams while TCP rides the L4 HTTP/3-CONNECT proxy. L4 cannot tunnel UDP
// (Cloudflare's proxy endpoint answers connect-udp with 403), so this leg gives
// UDP a real, tunneled, WARP-IP egress without giving up L4's per-flow QUIC TCP.
//
// It is deliberately lazy because mix mode targets workloads that are ~999/1000
// TCP: the tunnel is NOT built at startup and does NOT keepalive. It connects on
// the first UDP datagram, self-evicts ~30s after the last one (quic-go's default
// idle timeout, keepalive disabled), then sleeps until the next datagram wakes it
// via the demand channel. A mostly-TCP process therefore pays nothing for the UDP
// leg until UDP actually appears, and never holds a persistent second tunnel.
//
// Liveness is independent of the always-up L4 runtime: the SOCKS dialWithTarget
// closure routes by network *before* the runtime's tunnel gate, so a UDP datagram
// reaches DialUDP and its own `up` gate while TCP stays on L4.
type l3UDPTunnel struct {
	tunNet            *netstack.Net
	up                atomic.Bool
	demand            chan struct{} // cap-1: wakes the dormant MaintainTunnel loop
	connectionTimeout time.Duration
	idleTimeout       time.Duration

	startOnce sync.Once
	start     func() // launches MaintainTunnel exactly once, on first UDP demand
}

// DialUDP returns a tunneled UDP connection to addr (an IP literal:port; the SOCKS
// adapter resolves names locally before calling). The first call lazily brings the
// L3 leg up. While the leg is down it signals demand (waking a dormant reconnect
// loop) and returns ErrTunnelDisconnected so the caller drops the datagram and the
// client retries — matching the existing L3 UDP behavior.
func (t *l3UDPTunnel) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	t.startOnce.Do(t.start)

	if !t.up.Load() {
		t.signalDemand()
		return nil, ErrTunnelDisconnected
	}

	dialCtx, cancel := context.WithTimeout(ctx, t.connectionTimeout)
	defer cancel()

	conn, err := t.tunNet.DialContext(dialCtx, "udp", addr)
	if err != nil {
		// The leg may have died between the up gate and here. Mirror the proven L3
		// path (socksRuntime.DialContext): convert a down-race failure into the
		// sentinel the SOCKS layer understands and re-arm demand so the leg wakes.
		if !t.up.Load() {
			t.signalDemand()
			return nil, ErrTunnelDisconnected
		}
		return nil, err
	}
	return &models.TimeoutConn{
		Conn:        conn,
		IdleTimeout: t.idleTimeout,
	}, nil
}

// signalDemand records that UDP wants the tunnel while it is down so the lazy
// MaintainTunnel loop wakes and reconnects. Non-blocking; the cap-1 channel
// coalesces bursts into a single token. Mirrors socksRuntime.SignalDemand.
func (t *l3UDPTunnel) signalDemand() {
	select {
	case t.demand <- struct{}{}:
	default:
	}
}

// waitForReconnectDemand blocks until signalDemand fires or ctx is cancelled.
// Wired into api.ConnectionConfig.WaitForReconnectDemand.
func (t *l3UDPTunnel) waitForReconnectDemand(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.demand:
		return nil
	}
}

// drainDemand clears any pending token once the tunnel is up, so demand that piled
// up during a connect backoff doesn't trigger a spurious reconnect after the next
// idle drop.
func (t *l3UDPTunnel) drainDemand() {
	select {
	case <-t.demand:
	default:
	}
}

// startL3UDPTunnel builds (but does not yet connect) the parallel L3 UDP leg for
// mix mode. It reuses the L3 connect-ip machinery — the connect-ip SNI, the WARP
// endpoint pool, the netstack TUN device — but pins a lazy, keepalive-free,
// demand-gated lifecycle suited to rare UDP. The returned cleanup tears the leg
// down (cancel the maintain loop, then close the TUN device); it is safe to call
// even if no UDP ever arrived and the loop never started.
func startL3UDPTunnel(cmd *cobra.Command, connectionTimeout, idleTimeout time.Duration) (*l3UDPTunnel, func(), error) {
	// connect-ip leg uses the L3 SNI (socks.sni_address or ConnectSNI) — distinct
	// from the L4 proxy SNI used by the TCP leg.
	tlsConfig, err := prepareTlsConfig(cmd)
	if err != nil {
		return nil, nil, err
	}

	endpoint, endpointSelector, localAddresses, dnsAddrs, err := prepareNetworkConfig(cmd)
	if err != nil {
		return nil, nil, err
	}
	// connect-ip requires an HTTP/3 (UDP) endpoint; mix mode never uses HTTP/2
	// (setupAndRunL4Proxy rejects the combination), so this should always hold.
	if _, ok := endpoint.(*net.UDPAddr); !ok {
		return nil, nil, fmt.Errorf("l4_udp=tunnel requires a UDP endpoint, got %T", endpoint)
	}

	tunDev, tunNet, err := createTunDevice(localAddresses, dnsAddrs, cmd)
	if err != nil {
		return nil, nil, err
	}

	t := &l3UDPTunnel{
		tunNet:            tunNet,
		demand:            make(chan struct{}, 1),
		connectionTimeout: connectionTimeout,
		idleTimeout:       idleTimeout,
	}

	ctx, cancel := context.WithCancel(context.Background())

	reconnectLog := &api.TunnelReconnectLog{Trigger: "demand"}
	connCfg := api.ConnectionConfig{
		TLSConfig: tlsConfig,
		// Keepalive disabled on purpose: a 999/1000-TCP workload should let the UDP
		// leg self-evict (quic-go's ~30s default idle timeout) and sleep rather than
		// hold a persistent second tunnel. Active UDP traffic keeps the connection
		// alive on its own; a >30s lull simply drops one datagram and reconnects.
		KeepAlivePeriod:   0,
		InitialPacketSize: config.AppConfig.Socks.InitialPacketSize,
		Endpoint:          endpoint,
		EndpointSelector:  endpointSelector,
		UseHTTP2:          false,
		MTU:               config.AppConfig.Socks.MTU,
		// Force lazy reconnect regardless of socks.always_reconnect: the UDP leg must
		// stay dormant between rare datagrams, never eagerly rebuild after an idle
		// eviction. WaitForReconnectDemand parks it until the next UDP wakes it.
		AlwaysReconnect:        false,
		WaitForReconnectDemand: t.waitForReconnectDemand,
		ReconnectLog:           reconnectLog,
		ReconnectStrategy: &api.ExponentialBackoff{
			InitialDelay: config.AppConfig.Socks.ReconnectDelay.Duration(),
			MaxDelay:     5 * time.Minute,
			Factor:       2.0,
		},
		OnConnected: func() {
			t.up.Store(true)
			t.drainDemand()
			slog.Info("l4 mix: UDP tunnel up (parallel connect-ip leg)", "endpoint", endpoint.String())
		},
		OnDisconnected: func(err error) {
			t.up.Store(false)
			slog.Debug("l4 mix: UDP tunnel down; reconnects on next UDP demand", "error", err)
		},
	}

	t.start = func() {
		slog.Debug("l4 mix: first UDP datagram — bringing up the parallel L3 UDP tunnel")
		go api.MaintainTunnel(ctx, connCfg, api.NewNetstackAdapter(tunDev))
	}

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			// Cancel first so MaintainTunnel's forwarding supervisor unwinds its pump
			// goroutines before the TUN device disappears, then close the device.
			cancel()
			_ = tunDev.Close()
		})
	}
	return t, cleanup, nil
}
