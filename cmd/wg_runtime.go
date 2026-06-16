package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// newWGDeviceLogger bridges wireguard-go's logger to stdout. Errors are always
// emitted; verbose (handshake/transport) logging is gated on the verbose flag
// so it lines up with the SOCKS verbose-logging toggle.
func newWGDeviceLogger(verbose bool) *device.Logger {
	level := device.LogLevelError
	if verbose {
		level = device.LogLevelVerbose
	}
	return device.NewLogger(level, "(wg) ")
}

// StartWireGuardTunnel brings up an in-process WireGuard data plane over tunDev
// using wireguard-go's native device. This is the native use of the netstack
// fork (internal/netstack): the device reads plaintext IP packets from tunDev,
// encrypts them, and sends them out a real UDP socket via conn.NewDefaultBind.
//
// uapiConfig is the rendered UAPI "set" string (see wireguard.BuildUAPIConfig).
// On any failure the device is closed before returning so we never leak a bind.
func StartWireGuardTunnel(tunDev tun.Device, uapiConfig string, verbose bool) (*device.Device, error) {
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), newWGDeviceLogger(verbose))
	if err := dev.IpcSet(uapiConfig); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard IpcSet: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard Up: %w", err)
	}
	return dev, nil
}

// waitForWGHandshake polls the device until the peer reports a completed
// handshake or the timeout elapses. wireguard-go exposes no handshake event, so
// we read last_handshake_time_sec from IpcGet. A non-nil error means no
// handshake was observed in time; the caller may still choose to serve (a later
// keepalive can complete the handshake), but a slow/failed first request is the
// signal something is wrong with the peer/endpoint/credentials.
func waitForWGHandshake(dev *device.Device, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if wgHandshakeComplete(dev) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no wireguard handshake within %s", timeout)
		}
		<-ticker.C
	}
}

func wgHandshakeComplete(dev *device.Device) bool {
	cfg, err := dev.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(cfg, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			if sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && sec > 0 {
				return true
			}
		}
	}
	return false
}
