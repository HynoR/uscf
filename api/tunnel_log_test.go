package api

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/quic-go/quic-go"
)

func TestTunnelDisconnectReason_TransportError(t *testing.T) {
	err := fmt.Errorf("error reading from IP connection: %w", &quic.TransportError{
		ErrorCode:    quic.ProtocolViolation,
		ErrorMessage: "",
		Remote:       true,
	})
	reason, remote := TunnelDisconnectReason(err)
	if reason != "PROTOCOL_VIOLATION" {
		t.Fatalf("reason = %q, want PROTOCOL_VIOLATION", reason)
	}
	if !remote {
		t.Fatalf("remote = false, want true")
	}
}

func TestTunnelDisconnectReason_ClosedConnection(t *testing.T) {
	err := fmt.Errorf("error reading from IP connection: %w", net.ErrClosed)
	reason, remote := TunnelDisconnectReason(err)
	if reason != "connection_closed" {
		t.Fatalf("reason = %q, want connection_closed", reason)
	}
	if remote {
		t.Fatalf("remote = true, want false")
	}
}

func TestTunnelDisconnectReason_PrefersUnderlyingQUICError(t *testing.T) {
	inner := &quic.TransportError{ErrorCode: quic.ProtocolViolation, Remote: true}
	wrapped := fmt.Errorf("error writing to IP connection: %w", errors.Join(inner, net.ErrClosed))
	reason, remote := TunnelDisconnectReason(wrapped)
	if reason != "PROTOCOL_VIOLATION" {
		t.Fatalf("reason = %q, want PROTOCOL_VIOLATION", reason)
	}
	if !remote {
		t.Fatalf("remote = false, want true")
	}
}
