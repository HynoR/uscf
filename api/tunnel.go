package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/HynoR/uscf/internal"
	"golang.zx2c4.com/wireguard/tun"
)

var (
	connectTunnelFunc  = ConnectTunnel
	handleForwardingFn = handleForwarding
)

// NetBuffer is a pool of byte slices with a fixed capacity.
// Helps to reduce memory allocations and improve performance.
// It uses a sync.Pool to manage the byte slices.
// The capacity of the byte slices is set when the pool is created.
type NetBuffer struct {
	capacity int
	buf      sync.Pool
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) GetBuf() *[]byte {
	return n.buf.Get().(*[]byte)
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) PutBuf(buf *[]byte) {
	if cap(*buf) != n.capacity {
		return
	}
	n.buf.Put(buf)
}

// Get returns a byte slice from the pool.
func (n *NetBuffer) Get() []byte {
	return *(n.buf.Get().(*[]byte))
}

// Put places a byte slice back into the pool.
// It checks if the capacity of the byte slice matches the pool's capacity.
// If it doesn't match, the byte slice is not returned to the pool.
func (n *NetBuffer) Put(buf []byte) {
	if cap(buf) != n.capacity {
		return
	}
	n.buf.Put(&buf)
}

// NewNetBuffer creates a new NetBuffer with the specified capacity.
// The capacity must be greater than 0.
func NewNetBuffer(capacity int) *NetBuffer {
	if capacity <= 0 {
		panic("capacity must be greater than 0")
	}
	return &NetBuffer{
		capacity: capacity,
		buf: sync.Pool{
			New: func() interface{} {
				b := make([]byte, capacity)
				return &b
			},
		},
	}
}

// TunnelDevice abstracts a TUN device so that we can use the same tunnel-maintenance code
// regardless of the underlying implementation.
type TunnelDevice interface {
	// ReadPacket reads a packet from the device (using the given mtu) and returns its contents.
	ReadPacket(buf []byte) (int, error)
	// WritePacket writes a packet to the device.
	WritePacket(pkt []byte) error
}

// BatchTunnelDevice is an optional extension of TunnelDevice for devices that
// can return several packets per read (e.g. the forked netstack TUN). The
// forwarding supervisor type-asserts for it and falls back to single-packet
// ReadPacket otherwise.
type BatchTunnelDevice interface {
	// ReadPackets fills bufs with up to len(bufs) packets, recording each
	// packet's length in sizes, and returns the number of packets read.
	// It blocks until at least one packet is available.
	ReadPackets(bufs [][]byte, sizes []int) (int, error)
	// BatchSize is the maximum number of packets a single ReadPackets call
	// may return.
	BatchSize() int
}

// NetstackAdapter wraps a tun.Device (e.g. from netstack) to satisfy TunnelDevice.
type NetstackAdapter struct {
	dev            tun.Device
	packetBufsPool sync.Pool
	sizesPool      sync.Pool
}

func (n *NetstackAdapter) ReadPacket(buf []byte) (int, error) {

	packetBufs := n.packetBufsPool.Get().(*[][]byte)
	sizes := n.sizesPool.Get().(*[]int)

	defer func() {
		(*packetBufs)[0] = nil
		n.packetBufsPool.Put(packetBufs)
		n.sizesPool.Put(sizes)
	}()

	(*packetBufs)[0] = buf
	(*sizes)[0] = 0

	_, err := n.dev.Read(*packetBufs, *sizes, 0)
	if err != nil {
		return 0, err
	}

	return (*sizes)[0], nil
}

// ReadPackets implements BatchTunnelDevice by passing the caller's buffers
// straight to the device's batched Read.
func (n *NetstackAdapter) ReadPackets(bufs [][]byte, sizes []int) (int, error) {
	return n.dev.Read(bufs, sizes, 0)
}

// BatchSize implements BatchTunnelDevice.
func (n *NetstackAdapter) BatchSize() int {
	return n.dev.BatchSize()
}

func (n *NetstackAdapter) WritePacket(pkt []byte) error {
	// Write expects a slice of packet buffers.
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// NewNetstackAdapter creates a new NetstackAdapter.
func NewNetstackAdapter(dev tun.Device) TunnelDevice {
	return &NetstackAdapter{dev: dev,
		packetBufsPool: sync.Pool{
			New: func() interface{} {
				b := make([][]byte, 1)
				return &b
			},
		},
		sizesPool: sync.Pool{
			New: func() interface{} {
				b := make([]int, 1)
				return &b
			},
		},
	}
}

// ConnectionConfig 包含连接配置选项
type ConnectionConfig struct {
	TLSConfig            *tls.Config
	KeepAlivePeriod      time.Duration
	InitialPacketSize    uint16
	Endpoint             *net.UDPAddr
	EndpointSelector     func() *net.UDPAddr // Optional endpoint selector invoked for each connection attempt.
	MTU                  int
	MaxReconnectAttempts int // 连续连接失败达到阈值后暂停重连；0表示无限重试
	ReconnectStrategy    BackoffStrategy
	OnConnected          func()          // Optional callback after MASQUE connection is established.
	OnDisconnected       func(err error) // Optional callback after an established MASQUE connection is lost.

	// AlwaysReconnect, when true, rebuilds the tunnel immediately after it is
	// lost, even when idle. When false (default), a tunnel that was established
	// and then dropped is NOT rebuilt until there is fresh outbound demand —
	// Cloudflare closes idle tunnels after ~5 minutes (H3_NO_ERROR), so eagerly
	// reconnecting just to sit idle again wastes handshakes and fights that
	// idle-eviction policy. The very first connection is always eager.
	AlwaysReconnect bool
	// WaitForReconnectDemand blocks until there is outbound demand for the
	// tunnel (a SOCKS client wanting to dial, or pending outbound traffic), or
	// until ctx is cancelled. Only consulted when AlwaysReconnect is false and
	// an established connection was lost. Nil disables the gate (eager reconnect).
	WaitForReconnectDemand func(ctx context.Context) error
}

// BackoffStrategy 定义重连策略接口
type BackoffStrategy interface {
	NextDelay(attempt int) time.Duration
	Reset()
}

// ExponentialBackoff 实现指数退避重连策略
type ExponentialBackoff struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Factor       float64
}

func (b *ExponentialBackoff) NextDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return b.InitialDelay
	}

	// 计算指数退避延迟
	delay := b.InitialDelay
	maxDelayInFloat := float64(b.MaxDelay) / b.Factor
	for i := 0; i < attempt && float64(delay) < maxDelayInFloat; i++ {
		delay = time.Duration(float64(delay) * b.Factor)
	}

	// 确保不超过最大延迟
	if delay > b.MaxDelay {
		delay = b.MaxDelay
	}

	// 添加随机抖动以避免雷暴问题
	jitter := time.Duration(float64(delay) * 0.1) // 10%的抖动
	delay = delay - jitter + time.Duration(float64(jitter*2)*rand.Float64())

	return delay
}

func (b *ExponentialBackoff) Reset() {
	// 重置状态（如果需要）
}

// handleConnection 处理单次连接
func handleConnection(ctx context.Context, config ConnectionConfig, device TunnelDevice, reconnectAttempt int) (nextAttempt int, err error) {
	forwarding := newForwardingSupervisor(ctx, device, nil)
	defer forwarding.Close()
	return handleConnectionWithForwarding(ctx, config, forwarding, reconnectAttempt)
}

func handleConnectionWithForwarding(ctx context.Context, config ConnectionConfig, forwarding *forwardingSupervisor, reconnectAttempt int) (nextAttempt int, err error) {
	connected := false
	defer func() {
		if connected && config.OnDisconnected != nil {
			config.OnDisconnected(err)
		}
	}()

	endpoint := config.Endpoint
	if config.EndpointSelector != nil {
		if selected := config.EndpointSelector(); selected != nil {
			endpoint = selected
		}
	}
	if endpoint == nil || endpoint.IP == nil {
		return reconnectAttempt + 1, fmt.Errorf("no endpoint configured for tunnel connection")
	}

	slog.Info(
		"establishing MASQUE connection",
		"endpoint",
		fmt.Sprintf("%s:%d", endpoint.IP, endpoint.Port),
		"attempt",
		reconnectAttempt+1,
	)

	udpConn, tr, ipConn, rsp, err := connectTunnelFunc(
		ctx,
		config.TLSConfig,
		internal.DefaultQuicConfig(config.KeepAlivePeriod, config.InitialPacketSize),
		internal.ConnectURI,
		endpoint,
	)

	if err != nil {
		return reconnectAttempt + 1, err
	}
	defer func() {
		if ipConn != nil {
			ipConn.Close()
		}
		if udpConn != nil {
			udpConn.Close()
		}
		if tr != nil {
			tr.Close()
		}
	}()

	if rsp.StatusCode != 200 {
		return reconnectAttempt + 1, fmt.Errorf("tunnel connection failed: %s", rsp.Status)
	}

	slog.Info("connected to MASQUE server")
	connected = true
	if config.OnConnected != nil {
		config.OnConnected()
	}

	// 创建子上下文用于转发
	forwardingCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	forwardingErrCh := make(chan error, 1)
	go func() {
		forwardingErrCh <- handleForwardingFn(forwardingCtx, forwarding, ipConn)
	}()

	select {
	case err = <-forwardingErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("forwarding error", "error", err)
		}
		return 0, err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func MaintainTunnel(ctx context.Context, config ConnectionConfig, device TunnelDevice) {
	reconnectAttempt := 0
	var err error
	bufPool := NewNetBuffer(config.MTU)
	forwarding := newForwardingSupervisor(ctx, device, bufPool)
	defer forwarding.Close()

	for {
		select {
		case <-ctx.Done():
			slog.Info("context canceled, stopping tunnel maintenance")
			return
		default:
		}

		reconnectAttempt, err = handleConnectionWithForwarding(ctx, config, forwarding, reconnectAttempt)
		if ctx.Err() != nil {
			return
		}

		if err != nil {
			// reconnectAttempt == 0 means an established connection was lost
			// (connect failures return attempt+1). When lazy-reconnect is
			// enabled, don't rebuild the tunnel until there is fresh outbound
			// demand, so an idle tunnel that Cloudflare evicted stays down until
			// it is actually needed again.
			if reconnectAttempt == 0 && !config.AlwaysReconnect && config.WaitForReconnectDemand != nil {
				slog.Info("tunnel closed; waiting for outbound traffic before reconnecting")
				if werr := config.WaitForReconnectDemand(ctx); werr != nil {
					return
				}
				slog.Info("outbound traffic detected, reconnecting")
				config.ReconnectStrategy.Reset()
				continue
			}

			if config.MaxReconnectAttempts > 0 && reconnectAttempt >= config.MaxReconnectAttempts {
				slog.Error(
					"connection failed repeatedly, retry paused for manual intervention",
					"error",
					err,
					"attempts",
					reconnectAttempt,
					"max_reconnect_attempts",
					config.MaxReconnectAttempts,
				)
				<-ctx.Done()
				return
			}

			delay := config.ReconnectStrategy.NextDelay(reconnectAttempt)
			slog.Warn("connection error, retrying", "error", err, "delay", delay)

			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return
			}
		}

		config.ReconnectStrategy.Reset()
	}
}
