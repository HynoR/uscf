package logging

import (
	"log/slog"
	"os"
	"strings"

	"github.com/HynoR/uscf/config"
)

// Setup configures the process-wide default slog logger.
func Setup(cfg config.LoggingConfig) config.LoggingConfig {
	normalized, issues := config.NormalizeLoggingConfig(cfg)
	opts := &slog.HandlerOptions{
		Level: levelFromString(normalized.Level),
	}

	var handler slog.Handler
	switch normalized.Format {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	logger := slog.New(handler)
	slog.SetDefault(logger)

	if len(issues) > 0 {
		logger.Warn("invalid logging config; using defaults", "issues", strings.Join(issues, "; "))
	}

	return normalized
}

func levelFromString(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
