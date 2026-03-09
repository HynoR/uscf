# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM golang:1.26.0-alpine AS builder

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

# scratch won't be enough, because we need a cert store
FROM alpine:3.21

WORKDIR /app

# Create etc directory for configuration and install required tools
RUN mkdir -p /app/etc && \
    apk add --no-cache curl jq

COPY --from=builder /app/uscf /bin/uscf
# Copy the scripts from the build context
COPY entrypoint.sh /app/entrypoint.sh
COPY healthcheck.sh /app/healthcheck.sh
RUN chmod +x /app/entrypoint.sh /app/healthcheck.sh

# Add healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /app/healthcheck.sh

ENTRYPOINT ["/app/entrypoint.sh"]
