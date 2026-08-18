#!/bin/sh

set -u

# 读取 SOCKS 配置
CONFIG_DIR="${CONFIG_DIR:-/app/etc}"
CONFIG_PATH="${CONFIG_DIR}/config.json"
# uscf only writes the tunnel state file when USCF_TUNNEL_STATE_FILE is set
# (the image sets it). Unset means the feature is off on both sides, so fall
# through to the connectivity probe instead of failing on a missing file.
STATE_PATH="${USCF_TUNNEL_STATE_FILE:-}"
PORT=$(jq -r '.socks.port' "$CONFIG_PATH")
USERNAME=$(jq -r '.socks.username' "$CONFIG_PATH")
PASSWORD=$(jq -r '.socks.password' "$CONFIG_PATH")
BIND=$(jq -r '.socks.bind_address' "$CONFIG_PATH")

# 设置默认端口
if [ -z "$PORT" ] || [ "$PORT" = "null" ]; then
    PORT="1080"  # 默认端口
fi

# 探测地址跟随 bind_address：绑定到某个具体 IP 时,回环探测会在健康的容器上失败。
# 通配绑定(含 dual-stack 的 ::)一律走 IPv4 回环:容器里 IPv6 回环不保证存在。
case "$BIND" in
    ""|null|0.0.0.0|::) HOST="127.0.0.1" ;;
    \[*\]) HOST="$BIND" ;;
    *:*) HOST="[${BIND}]" ;;
    *) HOST="$BIND" ;;
esac

# 使用 curl 通过 SOCKS 代理检查连接；仅当 curl 返回码为0且 http code=204 时成功
check_url() {
    url="$1"
    http_code=""
    rc=0

    if [ -n "$USERNAME" ] && [ "$USERNAME" != "null" ] && [ -n "$PASSWORD" ] && [ "$PASSWORD" != "null" ]; then
        http_code=$(curl --silent --connect-timeout 5 --max-time 10 --socks5 "$HOST:$PORT" --proxy-user "$USERNAME:$PASSWORD" "$url" -o /dev/null -w "%{http_code}")
        rc=$?
    else
        http_code=$(curl --silent --connect-timeout 5 --max-time 10 --socks5 "$HOST:$PORT" "$url" -o /dev/null -w "%{http_code}")
        rc=$?
    fi

    if [ "$rc" -ne 0 ]; then
        return 1
    fi

    if [ "$http_code" = "204" ]; then
        return 0
    fi
    return 1
}

if [ -n "$STATE_PATH" ]; then
    if [ ! -f "$STATE_PATH" ]; then
        echo "[Health Check] Failed: tunnel state file missing ($STATE_PATH)"
        exit 1
    fi

    state=$(tr -d '[:space:]' < "$STATE_PATH")
    if [ "$state" != "up" ]; then
        echo "[Health Check] Failed: tunnel state is $state"
        exit 1
    fi
fi

if check_url "http://connectivitycheck.gstatic.com/generate_204"; then
    echo "[Health Check] OK(Google)"
    exit 0
fi

if check_url "http://cp.cloudflare.com/"; then
    echo "[Health Check] OK(Cloudflare)"
    exit 0
else
    echo "[Health Check] Failed!!!"
    exit 1
fi
