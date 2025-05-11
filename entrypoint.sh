#!/bin/sh
set -e

CONFIG_FILE="/etc/config.json"

echo "========================="
echo "Start USCF..."
echo "Conifg: $CONFIG_FILE"
echo "========================="


trap "echo \"Exit...\"; exit 0" TERM INT

exec /bin/uscf proxy -c "$CONFIG_FILE" "$@"
