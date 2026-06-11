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
