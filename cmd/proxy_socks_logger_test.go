package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestSocks5SlogLoggerDowngradesNoisyMessages(t *testing.T) {
	tests := []struct {
		name   string
		format string
		args   []interface{}
	}{
		{
			name:   "udp associate address notice",
			format: "client want to used addr %v, listen addr: %s",
			args:   []interface{}{"0.0.0.0:0", "64.118.140.63:63606"},
		},
		{
			name:   "configured udp 443 block",
			format: "connect to %v failed, %v",
			args:   []interface{}{"2a06:98c1:310b::ac40:9bd1:443", errUDP443Blocked},
		},
		{
			name:   "wrapped configured udp 443 block",
			format: "connect to %v failed, %v",
			args:   []interface{}{"2a06:98c1:310b::ac40:9bd1:443", fmt.Errorf("dial rejected: %w", errUDP443Blocked)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureSocks5LoggerOutput(func() {
				socks5SlogLogger{}.Errorf(tt.format, tt.args...)
			})

			if !strings.Contains(output, "level=DEBUG") {
				t.Fatalf("expected debug log, got: %s", output)
			}
			if strings.Contains(output, "level=ERROR") {
				t.Fatalf("expected no error log, got: %s", output)
			}
		})
	}
}

func TestSocks5SlogLoggerKeepsUnexpectedFailuresAtError(t *testing.T) {
	output := captureSocks5LoggerOutput(func() {
		socks5SlogLogger{}.Errorf("connect to %v failed, %v", "example.com:443", errors.New("network unreachable"))
	})

	if !strings.Contains(output, "level=ERROR") {
		t.Fatalf("expected error log, got: %s", output)
	}
}

func captureSocks5LoggerOutput(fn func()) string {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(previous)

	fn()
	return buf.String()
}
