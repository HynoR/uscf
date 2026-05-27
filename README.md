# USCF

USCF is an unofficial Cloudflare Warp proxy tool modified from [Usque](https://github.com/Diniboy1123/usque). It provides a SOCKS5 proxy through Cloudflare Warp and is packaged for two customer-facing runtime modes.

Before using this tool, you must accept and follow the [Cloudflare Terms of Service](https://www.cloudflare.com/application/terms/) and this repository's license. This project is provided as-is for experimentation and compatibility work.

## Which Mode Should I Use?

Most customers should start with usque mode.

| Need | Use | Deployment surface |
|---|---|---|
| Simple deployment with automatic free account registration | usque mode | Docker recommended; binary supported |
| Upgrade a normal deployment to WARP+ or Team | usque mode | Docker or binary |
| Domain or TCP-port split routing inside USCF | usque mode | Docker or binary |
| Standard WireGuard profile and `wg-quick` runtime | wg mode | Docker runtime only |
| Existing environment expects WireGuard routing | wg mode | Docker runtime only |

The same `uscf` binary supports both paths. Docker image tags and entrypoints choose the customer runtime:

- usque mode runs `uscf proxy`: MASQUE tunnel + SOCKS5 listener.
- wg mode runs `wg-quick` first, then `uscf socks`: WireGuard route + SOCKS5 listener.
- The WG runtime is packaged as the Docker image because it depends on container networking, `wg-quick`, route guards, and health checks. The binary `wg` subcommands are for account/profile preparation and upgrades.

Published Docker tags:

- usque stable: `latest`, version tags such as `0.14`.
- wg stable: `wg-latest`, `wg-<version>`.

Preview tags are maintainer-facing only:

- usque preview: `dev-<sha>`
- wg preview: `wg-dev-<sha>`

## Five-Minute Usque Deployment

Most customer deployments should use Docker.

Create a persistent config directory:

```bash
mkdir -p /etc/uscf
```

Run the default image:

```bash
docker run -d \
  --name uscf \
  --network=host \
  -v /etc/uscf:/app/etc \
  --log-driver json-file \
  --log-opt max-size=3m \
  --restart unless-stopped \
  ghcr.io/hynor/uscf:latest
```

On first startup, USCF registers a free Warp account and writes:

- `/etc/uscf/config.json`: reusable runtime settings such as SOCKS bind, port, auth, logging.
- `/etc/uscf/key.json`: usque account state and MASQUE identity such as `account_mode`, token, keys, endpoints, and assigned IPs.

To preconfigure the SOCKS listener before first run:

```bash
cp examples/usque-basic/config.json /etc/uscf/config.json
```

Then start the same container command above.

### Usque Binary Deployment

For non-Docker hosts, usque mode can run directly as a binary:

```bash
./uscf proxy -c /etc/uscf/config.json -b 0.0.0.0 -p 1080
```

The binary uses the same `config.json` + `key.json` split as Docker usque mode. WG runtime is not documented as a standalone binary deployment path.

## Upgrade Accounts

Account upgrades are the main place where the two modes differ. Pick the section that matches your deployed image.

### Usque: Free To WARP+

`uscf proxy --license` upgrades the account, saves state, and then keeps running the proxy. For Docker deployments, recreate the service container with the upgrade flag:

```bash
docker rm -f uscf

docker run -d \
  --name uscf \
  --network=host \
  -v /etc/uscf:/app/etc \
  --log-driver json-file \
  --log-opt max-size=3m \
  --restart unless-stopped \
  ghcr.io/hynor/uscf:latest \
  --license YOUR-WARP-PLUS-LICENSE
```

After successful startup, the upgraded account state is in `key.json`. You can leave the flag in your Docker command because future starts ignore it while `account_mode` is already `premium`, or remove it later and redeploy.

Binary equivalent, which also keeps running the proxy:

```bash
./uscf proxy -c /etc/uscf/config.json --license YOUR-WARP-PLUS-LICENSE
```

### Usque: Free To Team

Recreate the service container with a Zero Trust Team JWT:

```bash
docker rm -f uscf

docker run -d \
  --name uscf \
  --network=host \
  -v /etc/uscf:/app/etc \
  --log-driver json-file \
  --log-opt max-size=3m \
  --restart unless-stopped \
  ghcr.io/hynor/uscf:latest \
  --jwt YOUR-TEAM-JWT
```

You can also place a one-shot token beside `config.json`:

```bash
printf '%s\n' 'YOUR-TEAM-JWT' > /etc/uscf/jwt.txt
docker restart uscf
```

`jwt.txt` is consumed and cleared only when the current usque account is free and no upgrade flag is provided.

### Switching Usque Premium And Team

If `/etc/uscf/key.json` already has `"account_mode": "premium"` or `"account_mode": "team"`, USCF ignores new `--license` and `--jwt` flags to avoid accidental re-registration.

To intentionally switch account level:

1. Stop the `uscf` container.
2. Edit `/etc/uscf/key.json` and set `"account_mode": "free"`.
3. Recreate the container with the desired `--license` or `--jwt` startup flag.
4. After successful startup, optionally remove the flag from your Docker/Compose command and redeploy.

### WG Account Upgrades

WG mode uses `wg-account.json` and `wgcf.conf`, not `key.json`. After every WG account change, regenerate `wgcf.conf` and restart the WG container. These commands may be run from a local binary or inside a temporary helper container, but the supported WG runtime remains the Docker image.

Free to WARP+:

```bash
./uscf wg update \
  --wg-account /host/uscf/wg-account.json \
  --license YOUR-WARP-PLUS-LICENSE

./uscf wg generate \
  --wg-account /host/uscf/wg-account.json \
  --profile /host/uscf/wgcf.conf

docker restart uscf-wg
```

Free to Team:

```bash
./uscf wg register \
  --accept-tos \
  --jwt YOUR-TEAM-JWT \
  --wg-account /host/uscf/wg-account.json

./uscf wg generate \
  --wg-account /host/uscf/wg-account.json \
  --profile /host/uscf/wgcf.conf

docker restart uscf-wg
```

## WireGuard Mode

WG mode is advanced and Docker-only as a customer runtime. Use it when you specifically need WireGuard behavior.

First free deployment:

```bash
docker run -d \
  --name uscf-wg \
  --privileged \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.default.disable_ipv6=0 \
  -p 1080:1080 \
  -v /host/uscf:/app/etc \
  --restart unless-stopped \
  ghcr.io/hynor/uscf:wg-latest
```

First Team deployment:

```bash
docker run -d \
  --name uscf-wg \
  --privileged \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  --sysctl net.ipv6.conf.default.disable_ipv6=0 \
  -e WG_TEAM_JWT=YOUR-TEAM-JWT \
  -p 1080:1080 \
  -v /host/uscf:/app/etc \
  --restart unless-stopped \
  ghcr.io/hynor/uscf:wg-latest
```

Important WG rules:

- `--privileged` is required.
- IPv6 sysctls may be required if your container runtime disables IPv6.
- Empty-directory bootstrap creates `config.json`, `wg-account.json`, and `wgcf.conf`.
- Existing deployments need at least `config.json` and `wgcf.conf`.
- Partial state fails fast instead of trying to repair itself.
- `WG_TEAM_JWT` is ignored after deployment state exists.
- Runtime flags after the image name affect only `uscf socks`; they do not rewrite `config.json`.

## Split Routing And Advanced Parameters

Split routing applies to usque mode only:

- `socks.bypass_domain`: domains that should go directly through the current network.
- `socks.proxy_tcp_port`: TCP destination port allowlist for MASQUE. When non-empty, it takes priority over `bypass_domain`.

Start from `examples/usque-advanced/config.json`, then read [docs/config-reference.md](docs/config-reference.md) before enabling advanced routing, DNS, reconnect, or self-check options.

## Documentation

- [docs/deployment.md](docs/deployment.md): customer deployment, account upgrades, WG mode, troubleshooting.
- [docs/architecture.md](docs/architecture.md): two-mode architecture, image tags, files, runtime boundaries.
- [docs/config-reference.md](docs/config-reference.md): config fields grouped by common, usque-only, WG-only, and split routing.
- [examples/usque-basic/config.json](examples/usque-basic/config.json): minimal customer usque config.
- [examples/usque-advanced/config.json](examples/usque-advanced/config.json): advanced usque config with routing/DNS/reconnect fields.
- [examples/wg-basic/config.json](examples/wg-basic/config.json): minimal WG image SOCKS config.

Preview image publication rules for maintainers:

- `main` branch pushes validate Docker builds but do not publish images.
- Version tags pushed from the release flow publish stable tags for both regular and WG images.
- `dev` branch pushes publish commit-scoped preview tags only: `dev-<sha>` and `wg-dev-<sha>`.

## Build From Source

```bash
git clone https://github.com/HynoR/uscf.git
cd uscf
go build -o uscf .
```

## CLI Overview

Common commands:

```bash
./uscf proxy -c config.json
./uscf socks -c config.json -b 0.0.0.0
./uscf wg register --accept-tos --wg-account wg-account.json
./uscf wg generate --wg-account wg-account.json --profile wgcf.conf
./uscf wg update --wg-account wg-account.json --license YOUR-WARP-PLUS-LICENSE
```

`uscf socks` only loads reusable settings from `config.json`. It does not create a TUN device, does not establish MASQUE, and does not read `key.json`.

## Disclaimer

Do not use this tool for abuse. The tool mimics certain properties of official clients for stability and compatibility, but it is not an official Cloudflare client. You are responsible for any consequences that may arise from using it.

## License

This project is open source under the MIT License.
