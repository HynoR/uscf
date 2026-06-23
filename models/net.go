package models

import (
	"net"
	"sync/atomic"
	"time"
)

// 超时管理的连接包装器
type TimeoutConn struct {
	net.Conn
	IdleTimeout       time.Duration
	idleOverrideNs    atomic.Int64  // >0 overrides IdleTimeout; set via SetIdleTimeout
	idleGen           atomic.Uint64 // bumped on each SetIdleTimeout
	lastReadDeadline  atomic.Int64  // unix ns
	lastWriteDeadline atomic.Int64  // unix ns
}

// idle returns the currently effective re-arming idle timeout: the override set by
// SetIdleTimeout if any, otherwise the construction-time IdleTimeout.
func (c *TimeoutConn) idle() time.Duration {
	if v := c.idleOverrideNs.Load(); v > 0 {
		return time.Duration(v)
	}
	return c.IdleTimeout
}

// SetIdleTimeout lowers (or changes) the re-arming idle bound for an in-flight
// connection and forces the next Read/Write to re-arm at the new value, so a
// connection that is mid-relay can be given a shorter idle without first waiting
// out the previously-armed deadline. The bound still re-arms on activity, so an
// actively transferring direction is never cut — only a truly idle one is reaped
// at the new timeout. Safe for concurrent use with Read/Write.
func (c *TimeoutConn) SetIdleTimeout(d time.Duration) {
	c.idleOverrideNs.Store(int64(d))
	c.idleGen.Add(1)
	// Reset the "last armed" marks so the very next Read/Write re-arms at the new
	// (shorter) idle instead of reusing the old, far-future deadline.
	c.lastReadDeadline.Store(0)
	c.lastWriteDeadline.Store(0)
}

func (c *TimeoutConn) Read(b []byte) (int, error) {
	if idle := c.idle(); idle > 0 {
		now := time.Now()
		gen := c.idleGen.Load()
		last := c.lastReadDeadline.Load()
		if now.UnixNano()-last > int64(idle)/4 {
			if err := c.Conn.SetReadDeadline(now.Add(idle)); err != nil {
				return 0, err
			}
			c.lastReadDeadline.Store(now.UnixNano())
			// If SetIdleTimeout raced between idle() above and this arm, our deadline
			// may have used a stale (longer) idle and clobbered the shorter one it just
			// set. Re-arm with the current idle so the shorter bound always wins — this
			// is what keeps a half-open survivor from holding the old long deadline.
			if c.idleGen.Load() != gen {
				if err := c.Conn.SetReadDeadline(now.Add(c.idle())); err != nil {
					return 0, err
				}
			}
		}
	}
	return c.Conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (int, error) {
	if idle := c.idle(); idle > 0 {
		now := time.Now()
		gen := c.idleGen.Load()
		last := c.lastWriteDeadline.Load()
		if now.UnixNano()-last > int64(idle)/4 {
			if err := c.Conn.SetWriteDeadline(now.Add(idle)); err != nil {
				return 0, err
			}
			c.lastWriteDeadline.Store(now.UnixNano())
			if c.idleGen.Load() != gen {
				if err := c.Conn.SetWriteDeadline(now.Add(c.idle())); err != nil {
					return 0, err
				}
			}
		}
	}
	return c.Conn.Write(b)
}

// CloseWrite forwards a half-close to the underlying connection when it
// supports one (e.g. *net.TCPConn, gonet.TCPConn). net.Conn does not expose
// CloseWrite, so the embedded connection's method is not promoted automatically;
// this makes graceful TCP half-close work through the wrapper. Returns nil when
// the underlying connection has no write half to close.
func (c *TimeoutConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
