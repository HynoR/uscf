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
	"sync/atomic"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/HynoR/uscf/internal"
	"golang.zx2c4.com/wireguard/tun"
)

// packetBuffCap is the standard packet buffer capacity.
// 2*packetBuffCap serves as a soft cap threshold for returning buffers to the pool,
// preventing accidentally enlarged buffers from polluting the pool and causing memory bloat (pool poisoning).
// Production MTU < 1536, threshold 4096 provides sufficient headroom.
const packetBuffCap = 2048

const (
	forwardingErrStreakThreshold = 5
	forwardingErrBackoffBase     = 50 * time.Millisecond
	forwardingErrBackoffMax      = 2 * time.Second
)

var packetBufferPool *NetBuffer

var (
	connectTunnelFunc  = ConnectTunnel
	handleForwardingFn = handleForwarding
	runSelfCheckLoopFn = runSelfCheckLoop
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

// TunnelStats 用于跟踪隧道性能指标
// 所有字段都使用原子操作，无需加锁
type TunnelStats struct {
	PacketsIn       uint64
	PacketsOut      uint64
	BytesIn         uint64
	BytesOut        uint64
	Errors          uint64
	HandShake       uint64
	LastReconnectNs int64 // Unix 纳秒时间戳
}

func (s *TunnelStats) RecordPacketIn(bytes int) {
	atomic.AddUint64(&s.PacketsIn, 1)
	atomic.AddUint64(&s.BytesIn, uint64(bytes))
}

func (s *TunnelStats) RecordPacketOut(bytes int) {
	atomic.AddUint64(&s.PacketsOut, 1)
	atomic.AddUint64(&s.BytesOut, uint64(bytes))
}

func (s *TunnelStats) RecordError() {
	atomic.AddUint64(&s.Errors, 1)
}

func (s *TunnelStats) RecordHandShake() {
	atomic.AddUint64(&s.HandShake, 1)
	atomic.StoreInt64(&s.LastReconnectNs, time.Now().UnixNano())
}

// GetLastReconnect 返回最后一次重连的时间
func (s *TunnelStats) GetLastReconnect() time.Time {
	ns := atomic.LoadInt64(&s.LastReconnectNs)
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
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
	MaxPacketRate        float64 // 每秒最大数据包处理速率
	MaxBurst             int     // 突发处理数据包的最大数量
	MaxReconnectAttempts int     // 连续连接失败达到阈值后暂停重连；0表示无限重试
	SelfCheckEnabled     bool
	SelfCheckDialFunc    func(ctx context.Context, network, addr string) (net.Conn, error)
	ReconnectStrategy    BackoffStrategy
	OnConnected          func()          // Optional callback after MASQUE connection is established.
	OnDisconnected       func(err error) // Optional callback after an established MASQUE connection is lost.
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

func sleepWithBackoff(ctx context.Context, backoff *time.Duration) bool {
	if *backoff <= 0 {
		*backoff = forwardingErrBackoffBase
	} else if *backoff < forwardingErrBackoffMax {
		*backoff *= 2
		if *backoff > forwardingErrBackoffMax {
			*backoff = forwardingErrBackoffMax
		}
	}

	timer := time.NewTimer(*backoff)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// handleForwarding 处理数据包的转发
func handleForwarding(ctx context.Context, device TunnelDevice, ipConn *connectip.Conn, stats *TunnelStats) error {
	errChan := make(chan error, 2)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 从设备到IP连接的转发
	go func() {
		defer cancel()
		errStreak := 0
		var backoff time.Duration
		for {
			select {
			case <-ctx.Done():
				return
			default:
				buf := packetBufferPool.GetBuf()

				n, err := device.ReadPacket(*buf)
				if err != nil {
					packetBufferPool.PutBuf(buf)
					errChan <- fmt.Errorf("failed to read from TUN device: %v", err)
					return
				}

				stats.RecordPacketOut(n)
				icmp, err := ipConn.WritePacket((*buf)[:n])
				if err != nil {
					packetBufferPool.PutBuf(buf)
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while writing to IP connection: %v", err)
						return
					}
					errStreak++
					if errStreak >= forwardingErrStreakThreshold {
						errChan <- fmt.Errorf("too many write errors to IP connection: %w", err)
						return
					}
					if errStreak == 1 {
						slog.Debug("error writing to IP connection", "error", err, "streak", errStreak)
					}
					if !sleepWithBackoff(ctx, &backoff) {
						return
					}
					continue
				}
				errStreak = 0
				backoff = 0
				// Soft cap: buffers exceeding 2*packetBuffCap are not returned to pool, letting GC reclaim them to prevent pool poisoning
				if cap(*buf) < 2*packetBuffCap {
					packetBufferPool.PutBuf(buf)
				}

				if len(icmp) > 0 {
					if err := device.WritePacket(icmp); err != nil {
						if errors.As(err, new(*connectip.CloseError)) {
							errChan <- fmt.Errorf("failed to write ICMP to TUN device: %v", err)
							return
						}
						slog.Debug("error writing ICMP to TUN device; continuing", "error", err)
						continue
					}
					stats.RecordPacketIn(len(icmp))
				}
			}
		}
	}()

	// 从IP连接到设备的转发
	go func() {
		defer cancel()
		errStreak := 0
		var backoff time.Duration
		for {
			select {
			case <-ctx.Done():
				return
			default:
				buf := packetBufferPool.GetBuf()

				n, err := ipConn.ReadPacket(*buf, true)
				if err != nil {
					packetBufferPool.PutBuf(buf)
					if errors.As(err, new(*connectip.CloseError)) {
						errChan <- fmt.Errorf("connection closed while reading from IP connection: %v", err)
						return
					}
					errStreak++
					if errStreak >= forwardingErrStreakThreshold {
						errChan <- fmt.Errorf("too many read errors from IP connection: %w", err)
						return
					}
					if errStreak == 1 {
						slog.Debug("error reading from IP connection", "error", err, "streak", errStreak)
					}
					if !sleepWithBackoff(ctx, &backoff) {
						return
					}
					continue
				}
				errStreak = 0
				backoff = 0

				stats.RecordPacketIn(n)
				if err := device.WritePacket((*buf)[:n]); err != nil {
					packetBufferPool.PutBuf(buf)
					errChan <- fmt.Errorf("failed to write to TUN device: %v", err)
					return
				}
				// Soft cap: buffers exceeding 2*packetBuffCap are not returned to pool, letting GC reclaim them to prevent pool poisoning
				if cap(*buf) < 2*packetBuffCap {
					packetBufferPool.PutBuf(buf)
				}
			}
		}
	}()

	// 等待错误或上下文取消
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// monitorStats 监控统计信息
func monitorStats(ctx context.Context, stats *TunnelStats) {
	ticker := time.NewTicker(300 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			packetsIn := atomic.LoadUint64(&stats.PacketsIn)
			packetsOut := atomic.LoadUint64(&stats.PacketsOut)
			bytesIn := atomic.LoadUint64(&stats.BytesIn)
			bytesOut := atomic.LoadUint64(&stats.BytesOut)
			errors := atomic.LoadUint64(&stats.Errors)
			handShake := atomic.LoadUint64(&stats.HandShake)

			slog.Debug(
				"tunnel stats",
				"packets_in",
				packetsIn,
				"bytes_in",
				bytesIn,
				"packets_out",
				packetsOut,
				"bytes_out",
				bytesOut,
				"errors",
				errors,
				"handshake",
				handShake,
			)
		}
	}
}

// handleConnection 处理单次连接
func handleConnection(ctx context.Context, config ConnectionConfig, device TunnelDevice, stats *TunnelStats, reconnectAttempt int) (nextAttempt int, err error) {
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
		stats.RecordError()
		return reconnectAttempt + 1, fmt.Errorf("tunnel connection failed: %s", rsp.Status)
	}

	stats.RecordHandShake()
	slog.Info("connected to MASQUE server")
	connected = true
	if config.OnConnected != nil {
		config.OnConnected()
	}

	// 创建子上下文用于转发
	forwardingCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go monitorStats(forwardingCtx, stats)

	forwardingErrCh := make(chan error, 1)
	go func() {
		forwardingErrCh <- handleForwardingFn(forwardingCtx, device, ipConn, stats)
	}()

	var selfCheckErrCh <-chan error
	if config.SelfCheckEnabled {
		ch := make(chan error, 1)
		selfCheckErrCh = ch
		go func() {
			ch <- runSelfCheckLoopFn(forwardingCtx, config.SelfCheckDialFunc)
		}()
	}

	select {
	case err = <-forwardingErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("forwarding error", "error", err)
			stats.RecordError()
		}
		return 0, err
	case err = <-selfCheckErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			slog.Warn("self-check triggered reconnect", "error", err)
			stats.RecordError()
		}
		cancel()
		return 0, err
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func MaintainTunnel(ctx context.Context, config ConnectionConfig, device TunnelDevice) {
	stats := &TunnelStats{}
	reconnectAttempt := 0
	var err error
	packetBufferPool = NewNetBuffer(config.MTU)

	for {
		select {
		case <-ctx.Done():
			slog.Info("context canceled, stopping tunnel maintenance")
			return
		default:
		}

		reconnectAttempt, err = handleConnection(ctx, config, device, stats, reconnectAttempt)
		if ctx.Err() != nil {
			return
		}

		if err != nil {
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
