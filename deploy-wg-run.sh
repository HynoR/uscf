#!/bin/sh
set -eu

# Non-interactive Docker deploy + smoke test for the EXPERIMENTAL in-process
# WireGuard mode (`uscf proxy --wg --experimental`). Designed to be driven from
# env vars so it can be wired into automated test runs.
#
# Unlike the kernel-WireGuard image (runtime-wg / deploy-docker.sh "wg" mode),
# this image runs userspace WireGuard inside uscf and needs NO extra Linux
# capabilities — it is a plain unprivileged container.
#
# Usage:
#   ./deploy-wg-run.sh                 # build image, run container, smoke test (free account)
#   WG_TEAM_JWT=... ./deploy-wg-run.sh # register a Team/Zero-Trust account instead
#   BUILD=0 IMAGE=ghcr.io/hynor/uscf:wg-run ./deploy-wg-run.sh   # use a prebuilt image
#   SMOKE_TEST=0 ./deploy-wg-run.sh    # deploy only, skip the connectivity test
#
# Env vars (all optional; defaults shown):
#   IMAGE=uscf:wg-run-dev        Image tag to build and/or run
#   BUILD=1                      1 = docker build the runtime-wg-run target first
#   PLATFORM=                    e.g. linux/amd64 (uses buildx --load when set)
#   CONTAINER_NAME=uscf-wg-run   Container name
#   CONFIG_DIR=./.uscf-wg-run    Host dir bind-mounted to /app/etc (holds config + account)
#   SOCKS_PORT=1080              SOCKS5 port (published and used inside the container)
#   PUBLISH_ADDR=127.0.0.1       Host address to publish the SOCKS port on
#   SOCKS_USERNAME= / SOCKS_PASSWORD=   Optional SOCKS auth
#   WG_TEAM_JWT=                 Optional Team JWT (registers a Team account)
#   WG_RUN_KEEPALIVE=            Optional WG PersistentKeepalive (--wg-keepalive)
#   SMOKE_TEST=1                 1 = wait for healthy + curl a trace through the proxy
#   HEALTH_TIMEOUT=60            Seconds to wait for the container to become healthy

IMAGE="${IMAGE:-uscf:wg-run-dev}"
BUILD="${BUILD:-1}"
PLATFORM="${PLATFORM:-}"
CONTAINER_NAME="${CONTAINER_NAME:-uscf-wg-run}"
CONFIG_DIR="${CONFIG_DIR:-./.uscf-wg-run}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
PUBLISH_ADDR="${PUBLISH_ADDR:-127.0.0.1}"
SOCKS_USERNAME="${SOCKS_USERNAME:-}"
SOCKS_PASSWORD="${SOCKS_PASSWORD:-}"
WG_TEAM_JWT="${WG_TEAM_JWT:-}"
WG_RUN_KEEPALIVE="${WG_RUN_KEEPALIVE:-}"
SMOKE_TEST="${SMOKE_TEST:-1}"
HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-60}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker is not installed or not in PATH"

build_image() {
    say ">> building image ${IMAGE} (target runtime-wg-run)..."
    if [ -n "$PLATFORM" ]; then
        docker buildx build --platform "$PLATFORM" --load \
            --target runtime-wg-run -t "$IMAGE" "$SCRIPT_DIR"
    else
        docker build --target runtime-wg-run -t "$IMAGE" "$SCRIPT_DIR"
    fi
}

run_container() {
    if docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"; then
        say ">> removing existing container ${CONTAINER_NAME}..."
        docker rm -f "$CONTAINER_NAME" >/dev/null
    fi

    mkdir -p "$CONFIG_DIR"
    abs_config_dir=$(CDPATH= cd -- "$CONFIG_DIR" && pwd)

    say ">> starting container ${CONTAINER_NAME} from ${IMAGE}..."
    set -- docker run -d \
        --name "$CONTAINER_NAME" \
        -p "${PUBLISH_ADDR}:${SOCKS_PORT}:${SOCKS_PORT}" \
        -v "${abs_config_dir}:/app/etc" \
        -e "SOCKS_PORT=${SOCKS_PORT}" \
        -e "SOCKS_BIND_ADDRESS=0.0.0.0" \
        --restart unless-stopped

    [ -n "$SOCKS_USERNAME" ] && set -- "$@" -e "SOCKS_USERNAME=${SOCKS_USERNAME}"
    [ -n "$SOCKS_PASSWORD" ] && set -- "$@" -e "SOCKS_PASSWORD=${SOCKS_PASSWORD}"
    [ -n "$WG_TEAM_JWT" ] && set -- "$@" -e "WG_TEAM_JWT=${WG_TEAM_JWT}"
    [ -n "$WG_RUN_KEEPALIVE" ] && set -- "$@" -e "WG_RUN_KEEPALIVE=${WG_RUN_KEEPALIVE}"

    set -- "$@" "$IMAGE"
    "$@"
}

wait_for_health() {
    say ">> waiting up to ${HEALTH_TIMEOUT}s for ${CONTAINER_NAME} to become healthy..."
    i=0
    while [ "$i" -lt "$HEALTH_TIMEOUT" ]; do
        status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$CONTAINER_NAME" 2>/dev/null || echo "missing")
        case "$status" in
            healthy) say ">> container is healthy"; return 0 ;;
            unhealthy) say "!! container reported unhealthy"; return 1 ;;
            missing) say "!! container disappeared"; return 1 ;;
        esac
        if [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null || echo false)" != "true" ]; then
            say "!! container is not running"
            return 1
        fi
        i=$((i + 2))
        sleep 2
    done
    say "!! timed out waiting for healthy"
    return 1
}

smoke_test() {
    say ">> smoke test: curl https://1.1.1.1/cdn-cgi/trace through the SOCKS proxy..."
    auth=""
    if [ -n "$SOCKS_USERNAME" ]; then
        auth="--proxy-user ${SOCKS_USERNAME}:${SOCKS_PASSWORD}"
    fi
    # Run the curl from inside the container so we don't depend on host curl/socks.
    # shellcheck disable=SC2086
    if docker exec "$CONTAINER_NAME" curl -s --max-time 15 \
        --socks5-hostname "127.0.0.1:${SOCKS_PORT}" $auth \
        "https://1.1.1.1/cdn-cgi/trace"; then
        say ">> smoke test OK"
        return 0
    fi
    say "!! smoke test FAILED"
    return 1
}

[ "$BUILD" = "1" ] && build_image
run_container

say ""
say "Summary:"
say "  image:      ${IMAGE}"
say "  container:  ${CONTAINER_NAME}"
say "  config dir: ${CONFIG_DIR}  (config.json + wg-account.json live here)"
say "  socks:      ${PUBLISH_ADDR}:${SOCKS_PORT}  (experimental, in-process WireGuard)"
say ""

rc=0
if [ "$SMOKE_TEST" = "1" ]; then
    if wait_for_health && smoke_test; then
        rc=0
    else
        rc=1
        say ""
        say "Recent container logs:"
        docker logs --tail 40 "$CONTAINER_NAME" 2>&1 || true
    fi
fi

say ""
say "Useful commands:"
say "  docker logs -f ${CONTAINER_NAME}"
say "  curl -x socks5h://${PUBLISH_ADDR}:${SOCKS_PORT} https://1.1.1.1/cdn-cgi/trace"
say "  docker rm -f ${CONTAINER_NAME}"

exit "$rc"
