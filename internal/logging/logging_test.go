package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/HynoR/uscf/config"
)

func TestSetup_TextHandler(t *testing.T) {
	output := captureStderrOutput(t, func() {
		Setup(config.LoggingConfig{Level: "info", Format: "text"})
		slog.Info("text-output-check")
	})

	if !strings.Contains(output, "text-output-check") {
		t.Fatalf("expected text log output to contain message, got: %q", output)
	}
	if !strings.Contains(output, "level=INFO") {
		t.Fatalf("expected text log output to contain level, got: %q", output)
	}
}

func TestSetup_JSONHandler(t *testing.T) {
	output := captureStderrOutput(t, func() {
		Setup(config.LoggingConfig{Level: "info", Format: "json"})
		slog.Info("json-output-check")
	})

	if !strings.Contains(output, `"msg":"json-output-check"`) {
		t.Fatalf("expected json log output to contain message, got: %q", output)
	}
	if !strings.Contains(output, `"level":"INFO"`) {
		t.Fatalf("expected json log output to contain level, got: %q", output)
	}
}

func TestSetup_LevelFiltering(t *testing.T) {
	output := captureStderrOutput(t, func() {
		Setup(config.LoggingConfig{Level: "info", Format: "text"})
		slog.Debug("hidden-debug")
		slog.Info("visible-info")
	})

	if strings.Contains(output, "hidden-debug") {
		t.Fatalf("debug message should be filtered at info level, got: %q", output)
	}
	if !strings.Contains(output, "visible-info") {
		t.Fatalf("info message should be visible, got: %q", output)
	}
}

func TestSetup_InvalidConfigWarnsOnce(t *testing.T) {
	var normalized config.LoggingConfig
	output := captureStderrOutput(t, func() {
		normalized = Setup(config.LoggingConfig{Level: "bad-level", Format: "bad-format"})
	})

	if normalized.Level != "info" || normalized.Format != "text" {
		t.Fatalf("normalized = %+v, want level=info format=text", normalized)
	}

	warnCount := strings.Count(output, "invalid logging config; using defaults")
	if warnCount != 1 {
		t.Fatalf("expected exactly one warning for invalid config, got %d output=%q", warnCount, output)
	}
}

func captureStderrOutput(t *testing.T, fn func()) string {
	t.Helper()

	oldStderr := os.Stderr
	oldLogger := slog.Default()
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}

	os.Stderr = writePipe
	defer func() {
		os.Stderr = oldStderr
		slog.SetDefault(oldLogger)
		_ = readPipe.Close()
	}()

	fn()

	if err := writePipe.Close(); err != nil {
		t.Fatalf("close write pipe: %v", err)
	}

	bytes, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}

	return string(bytes)
}
