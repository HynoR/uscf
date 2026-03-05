#!/bin/sh

set -u

# 读取 SOCKS 配置
CONFIG_PATH="/app/etc/config.json"
STATE_PATH="${USCF_TUNNEL_STATE_FILE:-/tmp/uscf_tunnel_state}"
PORT=$(jq -r '.socks.port' $CONFIG_PATH)
USERNAME=$(jq -r '.socks.username' $CONFIG_PATH)
PASSWORD=$(jq -r '.socks.password' $CONFIG_PATH)

# 设置默认端口
if [ -z "$PORT" ] || [ "$PORT" = "null" ]; then
    PORT="1080"  # 默认端口
fi

# 使用 curl 通过 SOCKS 代理检查连接；仅当 curl 返回码为0且 http code=204 时成功
check_url() {
    url="$1"
    http_code=""
    rc=0

    if [ -n "$USERNAME" ] && [ "$USERNAME" != "null" ] && [ -n "$PASSWORD" ] && [ "$PASSWORD" != "null" ]; then
        http_code=$(curl --silent --connect-timeout 5 --max-time 10 --socks5 "127.0.0.1:$PORT" --proxy-user "$USERNAME:$PASSWORD" "$url" -o /dev/null -w "%{http_code}")
        rc=$?
    else
        http_code=$(curl --silent --connect-timeout 5 --max-time 10 --socks5 "127.0.0.1:$PORT" "$url" -o /dev/null -w "%{http_code}")
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

if [ ! -f "$STATE_PATH" ]; then
    echo "[Health Check] Failed: tunnel state file missing ($STATE_PATH)"
    exit 1
fi

state=$(tr -d '[:space:]' < "$STATE_PATH")
if [ "$state" != "up" ]; then
    echo "[Health Check] Failed: tunnel state is $state"
    exit 1
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
