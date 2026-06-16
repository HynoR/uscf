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
	lastReadDeadline  atomic.Int64 // unix ns
	lastWriteDeadline atomic.Int64 // unix ns
}

func (c *TimeoutConn) Read(b []byte) (int, error) {
	if c.IdleTimeout > 0 {
		now := time.Now()
		last := c.lastReadDeadline.Load()
		if now.UnixNano()-last > int64(c.IdleTimeout)/4 {
			if err := c.Conn.SetReadDeadline(now.Add(c.IdleTimeout)); err != nil {
				return 0, err
			}
			c.lastReadDeadline.Store(now.UnixNano())
		}
	}
	return c.Conn.Read(b)
}

func (c *TimeoutConn) Write(b []byte) (int, error) {
	if c.IdleTimeout > 0 {
		now := time.Now()
		last := c.lastWriteDeadline.Load()
		if now.UnixNano()-last > int64(c.IdleTimeout)/4 {
			if err := c.Conn.SetWriteDeadline(now.Add(c.IdleTimeout)); err != nil {
				return 0, err
			}
			c.lastWriteDeadline.Store(now.UnixNano())
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
