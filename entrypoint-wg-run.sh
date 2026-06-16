#!/bin/sh
set -eu

# Entrypoint for the EXPERIMENTAL in-process WireGuard run mode (`uscf wg run`).
#
# Unlike the kernel-WireGuard mode (entrypoint-wg-socks.sh, which needs
# wg-quick + NET_ADMIN + iptables), this mode runs a userspace WireGuard data
# plane inside uscf (gVisor netstack + wireguard-go) and exposes it as SOCKS5.
# It needs NO extra capabilities: just outbound UDP to the WARP endpoint and a
# listening TCP port for SOCKS. Run it as an ordinary unprivileged container.

CONFIG_DIR="${CONFIG_DIR:-/app/etc}"
SOCKS_CONFIG_PATH="${CONFIG_DIR}/config.json"
WG_ACCOUNT_PATH="${CONFIG_DIR}/wg-account.json"
USCF_BIN="${USCF_BIN:-/bin/uscf}"

SOCKS_BIND_ADDRESS="${SOCKS_BIND_ADDRESS:-0.0.0.0}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
SOCKS_USERNAME="${SOCKS_USERNAME:-}"
SOCKS_PASSWORD="${SOCKS_PASSWORD:-}"

# wg run tuning (all optional; empty => use the command's built-in defaults).
WG_RUN_MTU="${WG_RUN_MTU:-}"
WG_RUN_KEEPALIVE="${WG_RUN_KEEPALIVE:-}"
WG_RUN_LISTEN_PORT="${WG_RUN_LISTEN_PORT:-}"
WG_RUN_HANDSHAKE_TIMEOUT="${WG_RUN_HANDSHAKE_TIMEOUT:-}"
WG_RUN_EXTRA_ARGS="${WG_RUN_EXTRA_ARGS:-}"

# WG_TEAM_JWT (optional): register a Zero Trust / Team account instead of free.
WG_TEAM_JWT="$(printf '%s' "${WG_TEAM_JWT:-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

write_bootstrap_socks_config() {
    umask 077
    bind_json=$(json_escape "$SOCKS_BIND_ADDRESS")
    port_json=$(json_escape "$SOCKS_PORT")
    user_json=$(json_escape "$SOCKS_USERNAME")
    pass_json=$(json_escape "$SOCKS_PASSWORD")
    cat > "$SOCKS_CONFIG_PATH" <<EOF
{
  "socks": {
    "bind_address": "${bind_json}",
    "port": "${port_json}",
    "username": "${user_json}",
    "password": "${pass_json}"
  },
  "logging": {
    "level": "info",
    "format": "text",
    "socks_verbose": false
  }
}
EOF
    echo "wrote bootstrap ${SOCKS_CONFIG_PATH} (bind ${SOCKS_BIND_ADDRESS}:${SOCKS_PORT})"
}

bootstrap_if_needed() {
    mkdir -p "$CONFIG_DIR"

    if [ ! -f "$SOCKS_CONFIG_PATH" ]; then
        echo "no config.json found; bootstrapping a minimal SOCKS config..."
        write_bootstrap_socks_config
    fi

    if [ ! -f "$WG_ACCOUNT_PATH" ]; then
        if [ -n "$WG_TEAM_JWT" ]; then
            echo "no wg-account.json found; registering a Team account from WG_TEAM_JWT..."
            "$USCF_BIN" wg register --accept-tos --jwt "$WG_TEAM_JWT" --wg-account "$WG_ACCOUNT_PATH"
        else
            echo "no wg-account.json found; registering a free account..."
            "$USCF_BIN" wg register --accept-tos --wg-account "$WG_ACCOUNT_PATH"
        fi
    else
        if [ -n "$WG_TEAM_JWT" ]; then
            echo "WG_TEAM_JWT is ignored because wg-account.json already exists"
        fi
    fi
}

bootstrap_if_needed

echo "========================="
echo "Starting USCF in-process WireGuard run mode (EXPERIMENTAL)..."
echo "Config path:      $SOCKS_CONFIG_PATH"
echo "WG account path:  $WG_ACCOUNT_PATH"
echo "SOCKS bind:       ${SOCKS_BIND_ADDRESS}:${SOCKS_PORT}"
echo "========================="

# exec replaces this shell, so uscf becomes the container's main process and
# receives SIGTERM/SIGINT directly. The tuning vars are all space-free
# (numbers / durations like "30s"), so the conditional expansions are safe.
# shellcheck disable=SC2086
exec "$USCF_BIN" wg run --experimental \
    -c "$SOCKS_CONFIG_PATH" \
    --wg-account "$WG_ACCOUNT_PATH" \
    -b "$SOCKS_BIND_ADDRESS" \
    ${WG_RUN_MTU:+--mtu $WG_RUN_MTU} \
    ${WG_RUN_KEEPALIVE:+--keepalive $WG_RUN_KEEPALIVE} \
    ${WG_RUN_LISTEN_PORT:+--listen-port $WG_RUN_LISTEN_PORT} \
    ${WG_RUN_HANDSHAKE_TIMEOUT:+--handshake-timeout $WG_RUN_HANDSHAKE_TIMEOUT} \
    $WG_RUN_EXTRA_ARGS \
    "$@"
