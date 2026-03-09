#!/bin/sh
set -eu

CONFIG_PATH="/app/etc/config.json"
WG_CONFIG_PATH="/app/etc/wgcf.conf"
WG_INTERFACE="wgcf"

if [ ! -f "$CONFIG_PATH" ]; then
    echo "[Health Check] Failed: missing config.json ($CONFIG_PATH)"
    exit 1
fi

if [ ! -f "$WG_CONFIG_PATH" ]; then
    echo "[Health Check] Failed: missing wgcf.conf ($WG_CONFIG_PATH)"
    exit 1
fi

if ! wg show "$WG_INTERFACE" >/dev/null 2>&1; then
    echo "[Health Check] Failed: WireGuard interface $WG_INTERFACE is down"
    exit 1
fi

PORT=$(jq -r '.socks.port // "1080"' "$CONFIG_PATH")
USERNAME=$(jq -r '.socks.username // empty' "$CONFIG_PATH")
PASSWORD=$(jq -r '.socks.password // empty' "$CONFIG_PATH")

check_url() {
    url="$1"
    http_code=""
    rc=0

    if [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        http_code=$(curl --silent --connect-timeout 5 --max-time 10 --socks5 "127.0.0.1:$PORT" --proxy-user "$USERNAME:$PASSWORD" "$url" -o /dev/null -w "%{http_code}")
        rc=$?
    else
        http_code=$(curl --silent --connect-timeout 5 --max-time 10 --socks5 "127.0.0.1:$PORT" "$url" -o /dev/null -w "%{http_code}")
        rc=$?
    fi

    if [ "$rc" -ne 0 ]; then
        return 1
    fi

    [ "$http_code" = "204" ]
}

if check_url "http://cp.cloudflare.com/"; then
    echo "[Health Check] OK"
    exit 0
fi

echo "[Health Check] Failed: SOCKS5 request through WireGuard returned unexpected status"
exit 1
