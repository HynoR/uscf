#!/bin/sh

# 获取 SOCKS 端口
PORT=$(jq -r '.socks.port' /app/etc/config.json)
if [ -z "$PORT" ] || [ "$PORT" = "null" ]; then
    PORT="1080"  # 默认端口
fi

# 使用 curl 通过 SOCKS 代理检查连接
check_url() {
    curl --silent --connect-timeout 5 --max-time 10 -x "socks5h://127.0.0.1:$PORT" "$1" -o /dev/null -w "%{http_code}"
}

# 检查两个 URL
status_gstatic=$(check_url "http://connectivitycheck.gstatic.com/generate_204")
status_cloudflare=$(check_url "http://cp.cloudflare.com/")

# 如果任一检查返回 204，则认为服务健康
if [ "$status_gstatic" = "204" ] || [ "$status_cloudflare" = "204" ]; then
    exit 0
else
    exit 1
fi
