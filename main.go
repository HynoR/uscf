package main

import (
	"log/slog"
	"os"

	"github.com/HynoR/uscf/cmd"
	"github.com/HynoR/uscf/config"
	"github.com/HynoR/uscf/internal/logging"
)

func main() {
	logging.Setup(config.GetDefaultLoggingConfig())

	if err := cmd.Execute(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}
