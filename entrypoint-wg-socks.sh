#!/bin/sh
set -eu

CONFIG_DIR="${CONFIG_DIR:-/app/etc}"
WG_CONFIG_PATH="${CONFIG_DIR}/wgcf.conf"
WG_ACCOUNT_PATH="${CONFIG_DIR}/wg-account.json"
SOCKS_CONFIG_PATH="${CONFIG_DIR}/config.json"
SOCKS_BIND_ADDRESS="${SOCKS_BIND_ADDRESS:-0.0.0.0}"
WG_INTERFACE="${WG_INTERFACE:-wgcf}"
USCF_BIN="${USCF_BIN:-/bin/uscf}"
WG_QUICK_BIN="${WG_QUICK_BIN:-wg-quick}"
WG_BIN="${WG_BIN:-wg}"

WG_CONFIG_TMP_PATH="${WG_CONFIG_PATH}.tmp"
WG_ACCOUNT_TMP_PATH="${WG_ACCOUNT_PATH}.tmp"
SOCKS_CONFIG_TMP_PATH="${SOCKS_CONFIG_PATH}.tmp"

USCF_PID=""
WG_UP=0

cleanup_bootstrap_temps() {
    rm -f "$SOCKS_CONFIG_TMP_PATH" "$WG_ACCOUNT_TMP_PATH" "$WG_CONFIG_TMP_PATH"
}

cleanup() {
    trap - EXIT INT TERM
    cleanup_bootstrap_temps

    if [ -n "$USCF_PID" ]; then
        kill "$USCF_PID" 2>/dev/null || true
        wait "$USCF_PID" 2>/dev/null || true
        USCF_PID=""
    fi

    if [ "$WG_UP" -eq 1 ]; then
        echo "bringing down WireGuard interface ${WG_INTERFACE}..."
        "$WG_QUICK_BIN" down "$WG_CONFIG_PATH" >/dev/null 2>&1 || true
        WG_UP=0
    fi
}

on_signal() {
    echo "received termination signal, shutting down..."
    cleanup
    exit 0
}

write_bootstrap_config() {
    umask 077
    cat > "$SOCKS_CONFIG_TMP_PATH" <<'EOF'
{
  "socks": {
    "bind_address": "0.0.0.0",
    "port": "1080",
    "username": "",
    "password": ""
  },
  "logging": {
    "level": "info",
    "format": "text",
    "socks_verbose": false
  }
}
EOF
}

rollback_promoted_bootstrap_files() {
    rm -f "$SOCKS_CONFIG_PATH" "$WG_ACCOUNT_PATH" "$WG_CONFIG_PATH"
}

commit_bootstrap_files() {
    if ! mv -f "$SOCKS_CONFIG_TMP_PATH" "$SOCKS_CONFIG_PATH"; then
        return 1
    fi

    if ! mv -f "$WG_ACCOUNT_TMP_PATH" "$WG_ACCOUNT_PATH"; then
        rollback_promoted_bootstrap_files
        return 1
    fi

    if ! mv -f "$WG_CONFIG_TMP_PATH" "$WG_CONFIG_PATH"; then
        rollback_promoted_bootstrap_files
        return 1
    fi
}

bootstrap_if_needed() {
    config_exists=0
    profile_exists=0
    account_exists=0

    [ -f "$SOCKS_CONFIG_PATH" ] && config_exists=1
    [ -f "$WG_CONFIG_PATH" ] && profile_exists=1
    [ -f "$WG_ACCOUNT_PATH" ] && account_exists=1

    if [ "$config_exists" -eq 0 ] && [ "$profile_exists" -eq 0 ] && [ "$account_exists" -eq 0 ]; then
        echo "no WireGuard deployment state found; bootstrapping free account and profile..."

        write_bootstrap_config
        "$USCF_BIN" wg register --accept-tos --wg-account "$WG_ACCOUNT_TMP_PATH"
        "$USCF_BIN" wg generate --wg-account "$WG_ACCOUNT_TMP_PATH" --profile "$WG_CONFIG_TMP_PATH"
        commit_bootstrap_files

        echo "bootstrap completed; created config.json, wg-account.json, and wgcf.conf"
        return
    fi

    if [ "$config_exists" -eq 1 ] && [ "$profile_exists" -eq 1 ]; then
        if [ "$account_exists" -eq 0 ]; then
            echo "starting existing deployment without wg-account.json"
        fi
        return
    fi

    echo "partial deployment state in ${CONFIG_DIR}: expected config.json + wgcf.conf for existing deployment or none of config.json/wg-account.json/wgcf.conf for bootstrap" >&2
    exit 1
}

trap cleanup EXIT
trap on_signal INT TERM

mkdir -p "$CONFIG_DIR"
bootstrap_if_needed

echo "========================="
echo "Starting USCF SOCKS-only service with WireGuard egress..."
echo "WireGuard config path: $WG_CONFIG_PATH"
echo "WireGuard account path: $WG_ACCOUNT_PATH"
echo "SOCKS config path: $SOCKS_CONFIG_PATH"
echo "========================="

echo "bringing up WireGuard interface ${WG_INTERFACE}..."
"$WG_QUICK_BIN" up "$WG_CONFIG_PATH"
WG_UP=1

"$WG_BIN" show "$WG_INTERFACE" >/dev/null 2>&1

echo "starting uscf socks on ${SOCKS_BIND_ADDRESS}..."
"$USCF_BIN" socks -c "$SOCKS_CONFIG_PATH" -b "$SOCKS_BIND_ADDRESS" "$@" &
USCF_PID=$!

wait "$USCF_PID"
STATUS=$?
USCF_PID=""
exit "$STATUS"
