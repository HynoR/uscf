# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine AS builder

WORKDIR /app

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

COPY go.mod .
COPY go.sum .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

ENV GOEXPERIMENT=greenteagc

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -o uscf \
    -ldflags="-s -w -X github.com/HynoR/uscf/cmd.version=${VERSION} -X github.com/HynoR/uscf/cmd.commit=${COMMIT} -X github.com/HynoR/uscf/cmd.date=${BUILD_DATE}" .

FROM alpine:3.21 AS runtime-base

WORKDIR /app

RUN mkdir -p /app/etc && \
    apk add --no-cache curl jq

COPY --from=builder /app/uscf /bin/uscf

FROM runtime-base AS runtime-wg

RUN apk add --no-cache bash ca-certificates iproute2 iptables wireguard-tools

COPY entrypoint-wg-socks.sh /app/entrypoint-wg-socks.sh
COPY healthcheck-wg-socks.sh /app/healthcheck-wg-socks.sh

RUN chmod +x /app/entrypoint-wg-socks.sh /app/healthcheck-wg-socks.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /app/healthcheck-wg-socks.sh

ENTRYPOINT ["/app/entrypoint-wg-socks.sh"]

FROM runtime-base AS runtime-wg-run

# In-process (userspace) WireGuard run mode: gVisor netstack + wireguard-go
# inside uscf, exposed as SOCKS5. No kernel WireGuard, so NONE of
# wg-quick/iproute2/iptables/NET_ADMIN are needed — only outbound UDP and a
# listening TCP port. ca-certificates is required for the HTTPS registration
# call (`uscf wg register`).
RUN apk add --no-cache ca-certificates

# uscf writes the tunnel up/down state here and healthcheck.sh reads it back.
# Pinned explicitly so both sides agree regardless of the binary's default.
ENV USCF_TUNNEL_STATE_FILE=/tmp/uscf_tunnel_state

COPY entrypoint-wg-run.sh /app/entrypoint-wg-run.sh
COPY healthcheck.sh /app/healthcheck.sh

RUN chmod +x /app/entrypoint-wg-run.sh /app/healthcheck.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /app/healthcheck.sh

ENTRYPOINT ["/app/entrypoint-wg-run.sh"]

FROM runtime-base AS runtime-regular

# uscf writes the tunnel up/down state here and healthcheck.sh reads it back.
# Pinned explicitly so both sides agree regardless of the binary's default.
ENV USCF_TUNNEL_STATE_FILE=/tmp/uscf_tunnel_state

COPY entrypoint.sh /app/entrypoint.sh
COPY healthcheck.sh /app/healthcheck.sh

RUN chmod +x /app/entrypoint.sh /app/healthcheck.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /app/healthcheck.sh

ENTRYPOINT ["/app/entrypoint.sh"]
