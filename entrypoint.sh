#!/bin/sh
set -e

# Configuration file path
CONFIG_FILE="/app/etc/config.json"

echo "========================="
echo "Starting USCF proxy service..."
echo "Configuration file path: $CONFIG_FILE"
echo "========================="

# Catch SIGTERM and SIGINT signals for graceful exit
trap "echo \"Received termination signal, shutting down service...\"; exit 0" TERM INT

# Execute uscf proxy command, using the fixed configuration file path, and pass all additional command-line arguments
exec /bin/uscf proxy -c "$CONFIG_FILE" "$@"