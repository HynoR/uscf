# USCF Deployment Guide

This guide is written for customers who want a working SOCKS5 proxy first, then a clear path for account upgrades or WireGuard mode later. Docker is the main customer deployment path.

## Choose A Mode

Use usque mode unless you specifically need WireGuard behavior.

| Need | Use | Deployment surface |
|---|---|---|
| Normal deployment, simplest operation, automatic registration | usque mode | Docker recommended; binary supported |
| Upgrade a normal deployment to WARP+ or Team | usque mode | Docker or binary |
| A standard WireGuard profile and `wg-quick` behavior | wg mode | Docker runtime only |
| An environment that already expects WireGuard routing | wg mode | Docker runtime only |
| Domain or TCP-port split routing inside USCF | usque mode | Docker or binary |

## Five-Minute Usque Deployment

This is the recommended path for most customers.

Create a persistent directory:

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

On first startup, usque mode automatically registers a free account and writes:

- `/etc/uscf/config.json`
- `/etc/uscf/key.json`

The SOCKS5 proxy listens on the configured bind address and port. If you do not provide a config, the generated defaults come from USCF.

To preconfigure the listener before first run, copy `examples/usque-basic/config.json` into `/etc/uscf/config.json`.

### Usque Binary Deployment

Usque can also run without Docker:

```bash
./uscf proxy -c /etc/uscf/config.json -b 0.0.0.0 -p 1080
```

The binary uses the same split files as Docker usque mode: `config.json` for reusable runtime settings and `key.json` for account state.

## Usque Account Upgrade

Usque account state lives in `key.json`. The reusable listener settings stay in `config.json`.

### Free To WARP+

`uscf proxy --license` is a startup command. It upgrades the account, saves state, and then continues running the proxy. For Docker deployments, recreate the service container with the upgrade flag:

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

After the container has started successfully, the upgraded state is stored in `key.json`. You may leave the flag in your Docker/Compose command; future starts ignore it while `account_mode` is already `premium`. You may also remove the flag later and redeploy.

Equivalent binary command:

```bash
./uscf proxy -c /etc/uscf/config.json --license YOUR-WARP-PLUS-LICENSE
```

For binary deployments, this command also keeps running the proxy after the upgrade.

### Free To Team

`uscf proxy --jwt` follows the same startup behavior. For Docker deployments, recreate the service container with the Team JWT:

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

You can also place the token in a one-shot sibling file:

```bash
printf '%s\n' 'YOUR-TEAM-JWT' > /etc/uscf/jwt.txt
docker restart uscf
```

`jwt.txt` is consumed only when the current usque account is free and no `--license` or `--jwt` flag is provided. The file is cleared after a successful read.

### Switching Between Premium And Team

If `key.json` already says `account_mode` is `premium` or `team`, usque startup ignores new `--license` and `--jwt` flags. This prevents accidental re-registration.

To intentionally switch:

1. Stop the container.
2. Edit `/etc/uscf/key.json` and set `"account_mode": "free"`.
3. Recreate the container with the desired `--license` or `--jwt` startup flag.
4. After successful startup, optionally remove the flag from your Docker/Compose command and redeploy.

## WireGuard Mode

WG mode is an advanced Docker-only customer runtime for users who need `wg-quick` and a standard WireGuard profile. The `uscf wg` binary subcommands can prepare or upgrade account files, but the supported WG service runtime is the `wg-*` Docker image.

Requirements:

- Run with `--privileged`.
- Mount a writable `/app/etc`.
- Enable IPv6 sysctls if your container runtime disables IPv6.
- Expect full-tunnel WireGuard routing inside the container.

First deployment with a free WG account:

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

First deployment with a Team WG account:

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

`WG_TEAM_JWT` only works during empty-directory bootstrap. If any deployment state already exists, the image ignores it.

The WG image creates these files on first successful bootstrap:

- `/app/etc/config.json`
- `/app/etc/wg-account.json`
- `/app/etc/wgcf.conf`

Existing WG deployments must have at least `config.json` and `wgcf.conf`. Any partial state other than "all three missing" or "`config.json` plus `wgcf.conf` present" fails fast.

### Experimental In-Process WireGuard

For a single-binary alternative that needs neither `wg-quick` nor `--privileged`, `uscf proxy` can run an in-process WireGuard data plane and expose it directly as SOCKS5 — the same front door as the MASQUE transports, selected like `--l4`:

```bash
uscf proxy --wg --experimental                 # auto-registers wg-account.json, then serves SOCKS5
uscf proxy --wg --experimental --license <KEY>  # WARP+
uscf proxy --wg --experimental --jwt <TEAM-JWT> # Team
```

It auto-registers `wg-account.json` on first run (never touches `key.json`), reuses the shared `socks` config block, and persists `socks.wg: true` so a config-/Docker-driven run needs only `--experimental` thereafter. It is mutually exclusive with `--l4`/`--http2` (one transport per process).

A reconnect supervisor gives it runtime parity with the MASQUE transports: it watches the session and, when it wedges (sending but receiving nothing for ~3× `keepalive_period`), re-points the peer endpoint in place via UAPI — following a moved WARP edge without dropping the SOCKS listener — while gating new dials and resetting stranded connections during the outage. It remains **experimental**, not the supported production runtime; the `wg-*` Docker image above is still the recommended WG deployment.

## WG Account Upgrade

WG upgrades are explicit because `wgcf.conf` must be regenerated before the container can use the new account state.

### WG Free To WARP+

```bash
./uscf wg update \
  --wg-account /host/uscf/wg-account.json \
  --license YOUR-WARP-PLUS-LICENSE

./uscf wg generate \
  --wg-account /host/uscf/wg-account.json \
  --profile /host/uscf/wgcf.conf

docker restart uscf-wg
```

### WG Free To Team

Team mode creates a new WG account:

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

## Container Health Checks

Each image ships the check that matches its data plane:

| Image target | Entrypoint | Health check | What it proves |
|---|---|---|---|
| `runtime-regular` | `uscf proxy` (MASQUE L3, MASQUE L4, or `--wg`) | `healthcheck.sh` | Tunnel state file says `up`, then a real request through the SOCKS port returns 204 |
| `runtime-wg-run` | `uscf proxy --wg --experimental` | `healthcheck.sh` | Same as above |
| `runtime-wg` | `wg-quick up` + `uscf socks` | `healthcheck-wg-socks.sh` | Kernel interface is up, then a real request through the SOCKS port returns 204 |

The tunnel state file is the only part that needs wiring. uscf writes `up`/`down`
to `$USCF_TUNNEL_STATE_FILE` on every tunnel transition, and `healthcheck.sh`
reads it back to fail fast when the tunnel is known-down instead of waiting out a
proxy timeout. It is **opt-in**: with the variable unset uscf writes nothing (a
plain CLI run leaves no files behind) and `healthcheck.sh` skips the state gate
and goes straight to the connectivity probe. The images set it to
`/tmp/uscf_tunnel_state`, so both sides agree by construction.

The state follows the same signal that gates SOCKS dials, so it is identical
across transports — MASQUE L3 reconnects, MASQUE L4, and the in-process
WireGuard supervisor all report through it.

Both checks honor `CONFIG_DIR` and probe the address from `socks.bind_address`,
so relocating the config or binding to a specific IP does not make a healthy
container look broken.

## Troubleshooting

| Symptom | Check |
|---|---|
| usque container is unhealthy | Check `$USCF_TUNNEL_STATE_FILE` (`/tmp/uscf_tunnel_state` in the images) and the SOCKS bind address/port in `config.json`; see [Container Health Checks](#container-health-checks) |
| usque upgrade flags appear ignored | Check `account_mode` in `key.json`; existing `premium` or `team` accounts ignore upgrade flags |
| Team JWT file did nothing | Confirm the account is still free and the file is beside `config.json` as `jwt.txt` |
| WG container fails at startup | Check for partial state in `/app/etc`, missing `--privileged`, missing IPv6 sysctls, or no detectable default IPv4 route |
| WG upgrade did not take effect | Regenerate `wgcf.conf` after updating/registering the WG account, then restart the container |
| SOCKS auth or port is wrong in WG mode | CLI flags after the image name are runtime-only; edit `config.json` for persistent values |
