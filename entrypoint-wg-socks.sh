#!/bin/sh
set -eu

CONFIG_DIR="${CONFIG_DIR:-/app/etc}"
WG_CONFIG_PATH="${CONFIG_DIR}/wgcf.conf"
WG_ACCOUNT_PATH="${CONFIG_DIR}/wg-account.json"
SOCKS_CONFIG_PATH="${CONFIG_DIR}/config.json"
SOCKS_BIND_ADDRESS="${SOCKS_BIND_ADDRESS:-0.0.0.0}"
WG_INTERFACE="${WG_INTERFACE:-wgcf}"
WG_RUNTIME_CONFIG_PATH="${WG_RUNTIME_CONFIG_PATH:-/tmp/${WG_INTERFACE}.conf}"
USCF_BIN="${USCF_BIN:-/bin/uscf}"
WG_QUICK_BIN="${WG_QUICK_BIN:-wg-quick}"
WG_BIN="${WG_BIN:-wg}"
IP_BIN="${IP_BIN:-ip}"

WG_CONFIG_TMP_PATH="${WG_CONFIG_PATH}.tmp"
WG_ACCOUNT_TMP_PATH="${WG_ACCOUNT_PATH}.tmp"
SOCKS_CONFIG_TMP_PATH="${SOCKS_CONFIG_PATH}.tmp"

USCF_PID=""
WG_UP=0

cleanup_bootstrap_temps() {
    rm -f "$SOCKS_CONFIG_TMP_PATH" "$WG_ACCOUNT_TMP_PATH" "$WG_CONFIG_TMP_PATH"
}

cleanup_runtime_wg_config() {
    rm -f "$WG_RUNTIME_CONFIG_PATH"
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
        "$WG_QUICK_BIN" down "$WG_INTERFACE" >/dev/null 2>&1 || true
        WG_UP=0
    fi

    cleanup_runtime_wg_config
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

prepare_runtime_wg_config() {
    cleanup_runtime_wg_config

    runtime_basename=$(basename "$WG_RUNTIME_CONFIG_PATH")
    expected_runtime_basename="${WG_INTERFACE}.conf"
    if [ "$runtime_basename" != "$expected_runtime_basename" ]; then
        echo "WG_RUNTIME_CONFIG_PATH must end with /${expected_runtime_basename}" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$WG_RUNTIME_CONFIG_PATH")"

    default_v4_route=$("$IP_BIN" -4 route show default | head -n 1 || true)
    if [ -z "$default_v4_route" ]; then
        echo "failed to detect default IPv4 route before wg-quick up" >&2
        exit 1
    fi

    default_v4_dev=$(printf '%s\n' "$default_v4_route" | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    if [ -z "$default_v4_dev" ]; then
        echo "failed to parse default IPv4 route device from: $default_v4_route" >&2
        exit 1
    fi

    default_v4_route_get=$("$IP_BIN" -4 route get 1.1.1.1 | head -n 1 || true)
    default_v4_addr=$(printf '%s\n' "$default_v4_route_get" | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')
    if [ -z "$default_v4_addr" ]; then
        echo "failed to detect source IPv4 address on $default_v4_dev before wg-quick up" >&2
        exit 1
    fi

    default_v6_route=$("$IP_BIN" -6 route show default | head -n 1 || true)
    default_v6_addr=""
    if [ -n "$default_v6_route" ]; then
        default_v6_dev=$(printf '%s\n' "$default_v6_route" | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
        if [ -n "$default_v6_dev" ]; then
            default_v6_route_get=$("$IP_BIN" -6 route get 2606:4700:4700::1111 | head -n 1 || true)
            default_v6_addr=$(printf '%s\n' "$default_v6_route_get" | awk '{for (i = 1; i <= NF; i++) if ($i == "src") { print $(i + 1); exit }}')
        fi
    fi

    echo "detected main route guard source IPv4 ${default_v4_addr} on ${default_v4_dev}"
    if [ -n "$default_v6_addr" ]; then
        echo "detected main route guard source IPv6 ${default_v6_addr}"
    fi

    if grep -Eq '^[[:space:]]*DNS[[:space:]]*=' "$WG_CONFIG_PATH"; then
        echo "ignoring DNS directives in wgcf.conf for container mode; leaving /etc/resolv.conf unchanged"
    fi

    if ! awk \
        -v post_up_v4="PostUp = $IP_BIN rule add from ${default_v4_addr}/32 lookup main" \
        -v post_down_v4="PostDown = $IP_BIN rule delete from ${default_v4_addr}/32 lookup main" \
        -v post_up_v6="${default_v6_addr:+PostUp = $IP_BIN -6 rule add from ${default_v6_addr}/128 lookup main}" \
        -v post_down_v6="${default_v6_addr:+PostDown = $IP_BIN -6 rule delete from ${default_v6_addr}/128 lookup main}" \
        '
        /^[[:space:]]*DNS[[:space:]]*=.*/ { next }
        {
            print
            if (!inserted && $0 ~ /^\[Interface\][[:space:]]*$/) {
                print post_up_v4
                print post_down_v4
                if (post_up_v6 != "") print post_up_v6
                if (post_down_v6 != "") print post_down_v6
                inserted = 1
            }
        }
        END {
            if (!inserted) exit 1
        }
        ' "$WG_CONFIG_PATH" > "$WG_RUNTIME_CONFIG_PATH"; then
        echo "failed to build runtime wg config from $WG_CONFIG_PATH" >&2
        exit 1
    fi
    chmod 600 "$WG_RUNTIME_CONFIG_PATH"
}

bootstrap_if_needed() {
    config_exists=0
    profile_exists=0
    account_exists=0
    team_jwt=$(printf '%s' "${WG_TEAM_JWT:-}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

    [ -f "$SOCKS_CONFIG_PATH" ] && config_exists=1
    [ -f "$WG_CONFIG_PATH" ] && profile_exists=1
    [ -f "$WG_ACCOUNT_PATH" ] && account_exists=1

    if [ "$config_exists" -eq 0 ] && [ "$profile_exists" -eq 0 ] && [ "$account_exists" -eq 0 ]; then
        if [ -n "$team_jwt" ]; then
            echo "no WireGuard deployment state found; bootstrapping team account and profile from WG_TEAM_JWT..."
        else
            echo "no WireGuard deployment state found; bootstrapping free account and profile..."
        fi

        write_bootstrap_config
        if [ -n "$team_jwt" ]; then
            "$USCF_BIN" wg register --accept-tos --jwt "$team_jwt" --wg-account "$WG_ACCOUNT_TMP_PATH"
        else
            "$USCF_BIN" wg register --accept-tos --wg-account "$WG_ACCOUNT_TMP_PATH"
        fi
        "$USCF_BIN" wg generate --wg-account "$WG_ACCOUNT_TMP_PATH" --profile "$WG_CONFIG_TMP_PATH"
        commit_bootstrap_files

        echo "bootstrap completed; created config.json, wg-account.json, and wgcf.conf"
        return
    fi

    if [ "$config_exists" -eq 1 ] && [ "$profile_exists" -eq 1 ]; then
        if [ -n "$team_jwt" ]; then
            echo "WG_TEAM_JWT is ignored because WireGuard deployment state already exists"
        fi
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

prepare_runtime_wg_config

echo "bringing up WireGuard interface ${WG_INTERFACE}..."
"$WG_QUICK_BIN" up "$WG_RUNTIME_CONFIG_PATH"
WG_UP=1

"$WG_BIN" show "$WG_INTERFACE" >/dev/null 2>&1

echo "starting uscf socks on ${SOCKS_BIND_ADDRESS}..."
"$USCF_BIN" socks -c "$SOCKS_CONFIG_PATH" -b "$SOCKS_BIND_ADDRESS" "$@" &
USCF_PID=$!

wait "$USCF_PID"
STATUS=$?
USCF_PID=""
exit "$STATUS"
