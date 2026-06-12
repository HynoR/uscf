package netstack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// TestStackTransportOptions asserts every TCP option CreateNetTUN configures
// round-trips through the stack, so a silently ignored option cannot regress
// unnoticed.
func TestStackTransportOptions(t *testing.T) {
	nt, _ := newTestTUN(t)

	var sack tcpip.TCPSACKEnabled
	if err := nt.stack.TransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		t.Fatalf("get SACK: %v", err)
	}
	if !bool(sack) {
		t.Error("TCP SACK not enabled")
	}

	var sndBuf tcpip.TCPSendBufferSizeRangeOption
	if err := nt.stack.TransportProtocolOption(tcp.ProtocolNumber, &sndBuf); err != nil {
		t.Fatalf("get send buffer range: %v", err)
	}
	want := tcpip.TCPSendBufferSizeRangeOption{Min: tcpMinBufferSize, Default: tcpDefaultBufferSize, Max: tcpMaxBufferSize}
	if sndBuf != want {
		t.Errorf("send buffer range = %+v, want %+v", sndBuf, want)
	}

	var rcvBuf tcpip.TCPReceiveBufferSizeRangeOption
	if err := nt.stack.TransportProtocolOption(tcp.ProtocolNumber, &rcvBuf); err != nil {
		t.Fatalf("get receive buffer range: %v", err)
	}
	wantRcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcpMinBufferSize, Default: tcpDefaultBufferSize, Max: tcpMaxBufferSize}
	if rcvBuf != wantRcv {
		t.Errorf("receive buffer range = %+v, want %+v", rcvBuf, wantRcv)
	}

	var moderate tcpip.TCPModerateReceiveBufferOption
	if err := nt.stack.TransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		t.Fatalf("get receive buffer moderation: %v", err)
	}
	if !bool(moderate) {
		t.Error("TCP receive buffer moderation not enabled")
	}

	var cc tcpip.CongestionControlOption
	if err := nt.stack.TransportProtocolOption(tcp.ProtocolNumber, &cc); err != nil {
		t.Fatalf("get congestion control: %v", err)
	}
	if string(cc) != "cubic" {
		t.Errorf("congestion control = %q, want %q", cc, "cubic")
	}

	var delay tcpip.TCPDelayEnabled
	if err := nt.stack.TransportProtocolOption(tcp.ProtocolNumber, &delay); err != nil {
		t.Fatalf("get TCP delay: %v", err)
	}
	if bool(delay) {
		t.Error("TCP delay (Nagle) should be disabled")
	}
}
