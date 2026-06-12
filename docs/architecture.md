# USCF Runtime Architecture

USCF ships one binary with two customer-facing runtime modes. The mode is selected by the image tag and entrypoint, not by a shared `mode` field in JSON.

## Mode Matrix

| Mode | Customer fit | Deployment surface | Image tags | Entrypoint | Main command | Network path |
|---|---|---|---|---|---|---|
| usque | Default path for most users | Docker recommended; binary supported | `latest`, version tags such as `0.14` | `/app/entrypoint.sh` | `uscf proxy -c /app/etc/config.json` | MASQUE tunnel, netstack TUN, SOCKS5 listener |
| wg | Advanced path for WireGuard-specific environments | Docker runtime only | `wg-latest`, `wg-<version>` | `/app/entrypoint-wg-socks.sh` | `wg-quick up` then `uscf socks -c /app/etc/config.json` | WireGuard default route, direct SOCKS5 listener |

Both modes expose a SOCKS5 proxy. The difference is how outbound traffic reaches Cloudflare Warp.

Most customers deploy through Docker. Usque mode can also run directly as a binary with `uscf proxy`. WG runtime is intentionally documented as Docker-only because the customer runtime depends on the image entrypoint, installed `wireguard-tools`, `wg-quick`, container route guards, and Docker health checks. The binary `uscf wg` commands are account/profile management helpers, not the WG runtime service.

## Configuration Files

New deployments should use split configuration files:

| File | Used by | Contents |
|---|---|---|
| `config.json` | usque and wg | Reusable runtime settings: SOCKS bind/port/auth, logging, registration name, custom MASQUE endpoints |
| `key.json` | usque only | MASQUE identity and account state: `private_key`, `endpoint_*`, `account_mode`, `license`, `id`, `access_token`, assigned IPs |
| `wg-account.json` | wg account management | Standalone WireGuard account state: device id, token, license, WireGuard private key |
| `wgcf.conf` | wg runtime | WireGuard profile consumed by `wg-quick` |
| `jwt.txt` | usque only | Optional one-shot Team JWT beside `config.json`; consumed and cleared by `uscf proxy` when the current account is free |

Legacy single-file `config.json` is still accepted for compatibility. On load, USCF migrates identity fields into sibling `key.json`. New customer docs and examples should not teach the legacy layout.

## Account Levels

Account level is independent from runtime mode:

| Level | Meaning | usque state | wg state |
|---|---|---|---|
| `free` | Default Warp account | Stored in `key.json` | Stored in `wg-account.json` |
| `premium` | WARP+ license account | Created or switched with `uscf proxy --license` while current mode is free/invalid | Rebound with `uscf wg update --license`, then `uscf wg generate` |
| `team` | Zero Trust Team account | Created or switched with `uscf proxy --jwt` while current mode is free/invalid | Created with `uscf wg register --jwt`, then `uscf wg generate` |

If an existing usque account is already `premium` or `team`, startup ignores `--license` and `--jwt`. To switch to another account level, set `account_mode` in `key.json` back to `free` first, then run the desired upgrade command.

## Runtime Boundaries

- In usque mode, `proxy` owns registration, account switching, MASQUE key enrollment, TUN setup, routing policy, DNS policy, and the SOCKS listener.
- In wg mode, the Docker entrypoint owns WireGuard bootstrap and `wg-quick`; `uscf socks` only exposes SOCKS over the container network route.
- `uscf socks` does not read `key.json`, does not create a MASQUE tunnel, and ignores tunnel-only settings such as `bypass_domain`, `proxy_tcp_port`, custom endpoints, remote DNS, and MASQUE identity fields.
- `proxy` CLI overrides for bind address, port, username, password, and `use_ipv6` are saved back to config.
- `socks` CLI overrides in the WG image are runtime-only and do not rewrite `config.json`.
- `WG_TEAM_JWT` is only consumed by the WG image when all three files are missing: `config.json`, `wg-account.json`, and `wgcf.conf`.

## Health Checks

| Mode | Health check |
|---|---|
| usque | Requires the tunnel state file to be `up`, then performs a SOCKS request to a connectivity endpoint |
| wg | Requires `config.json`, `wgcf.conf`, a live `wgcf` interface from `wg show`, then performs a SOCKS request through WireGuard |

In both modes, Docker restart policy is the outer recovery mechanism. The usque tunnel also has an internal reconnect loop; the WG image relies on container health and restart behavior for full WireGuard recovery.

## Release Channels

- Stable customer images come only from version tags on `main`: `latest`, `<version>`, `wg-latest`, and `wg-<version>`.
- Internal preview images come only from `dev` branch commits: moving tags `dev` and `wg-dev`, plus commit-scoped tags `dev-<sha>` and `wg-dev-<sha>`.
- `main` branch pushes without a version tag validate the Docker targets but do not publish images.
