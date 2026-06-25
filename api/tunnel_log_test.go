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

// closeCauseTransport is a fake tunnelTransport exposing a fixed close cause.
type closeCauseTransport struct{ cause error }

func (closeCauseTransport) Close() error        { return nil }
func (t closeCauseTransport) CloseCause() error { return t.cause }

func TestEnrichWithTunnelCloseCause_UnmasksClosedConnection(t *testing.T) {
	// The forwarding read surfaced a masked net.ErrClosed, but the QUIC connection
	// closed with an application error (e.g. Cloudflare idle eviction, H3_NO_ERROR).
	masked := fmt.Errorf("error reading from IP connection: %w", net.ErrClosed)
	tr := closeCauseTransport{cause: &quic.ApplicationError{ErrorCode: 0, Remote: true}}

	enriched := enrichWithTunnelCloseCause(masked, tr)

	reason, remote := TunnelDisconnectReason(enriched)
	if reason != "application_0" {
		t.Fatalf("reason = %q, want application_0 (the real QUIC cause, not connection_closed)", reason)
	}
	if !remote {
		t.Fatalf("remote = false, want true (peer-initiated close)")
	}
}

func TestEnrichWithTunnelCloseCause_NoCauseLeavesErrorUnchanged(t *testing.T) {
	masked := fmt.Errorf("error reading from IP connection: %w", net.ErrClosed)

	// Transport with no live close cause (connection still alive): unchanged.
	if got := enrichWithTunnelCloseCause(masked, closeCauseTransport{cause: nil}); got != masked {
		t.Fatalf("expected unchanged error when cause is nil, got %v", got)
	}

	// Transport that doesn't implement CloseCause (e.g. HTTP/2): unchanged.
	if got := enrichWithTunnelCloseCause(masked, closeFunc(func() error { return nil })); got != masked {
		t.Fatalf("expected unchanged error for non-causer transport, got %v", got)
	}
}
