package api

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/quic-go/quic-go"
)

// TunnelDisconnectReason normalizes a tunnel forwarding error into a short reason
// label and whether the close was initiated by the remote peer.
func TunnelDisconnectReason(err error) (reason string, remote bool) {
	if err == nil {
		return "unknown", false
	}

	if reason, remote, ok := tunnelQUICDisconnectReason(err); ok {
		return reason, remote
	}

	msg := stripTunnelErrorPrefix(err.Error())
	if msg == "" {
		return "unknown", false
	}
	if errors.Is(err, net.ErrClosed) || strings.Contains(msg, "use of closed network connection") {
		return "connection_closed", false
	}
	return msg, false
}

func tunnelQUICDisconnectReason(err error) (reason string, remote bool, ok bool) {
	if err == nil {
		return "", false, false
	}
	if te, ok := err.(*quic.TransportError); ok {
		return transportErrorReason(te), te.Remote, true
	}
	if ae, ok := err.(*quic.ApplicationError); ok {
		return fmt.Sprintf("application_%d", ae.ErrorCode), ae.Remote, true
	}
	if joined, isJoined := err.(interface{ Unwrap() []error }); isJoined {
		for _, e := range joined.Unwrap() {
			if reason, remote, ok := tunnelQUICDisconnectReason(e); ok {
				return reason, remote, true
			}
		}
		return "", false, false
	}
	if child := errors.Unwrap(err); child != nil {
		return tunnelQUICDisconnectReason(child)
	}
	return "", false, false
}

func transportErrorReason(te *quic.TransportError) string {
	if te == nil {
		return "transport_error"
	}
	code := te.ErrorCode.String()
	if code != "" {
		return code
	}
	return fmt.Sprintf("transport_%d", te.ErrorCode)
}

func stripTunnelErrorPrefix(msg string) string {
	msg = strings.TrimSpace(msg)
	for _, prefix := range []string{
		"error reading from IP connection: ",
		"error writing to IP connection: ",
		"failed to read from TUN device: ",
		"failed to write to TUN device: ",
	} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return strings.TrimSpace(msg)
}
