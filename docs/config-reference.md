# USCF Configuration Reference

USCF uses split configuration files for new deployments.

- `config.yaml` is reusable runtime configuration (YAML; the preferred format).
- `key.json` is usque account and MASQUE identity state (always JSON).
- `wg-account.json` and `wgcf.conf` are WG-mode state files.

### Config format and migration

The reusable config is YAML. A legacy `config.json` is still read transparently
(JSON is valid YAML), so existing deployments keep working. On the next
`uscf proxy` run with no explicit `--config`, a lone `config.json` is auto-upgraded:
its contents are transcoded to `config.yaml` and the original is renamed to
`config.json.bak`. `key.json` is never converted — identity material stays JSON.

Path resolution when `--config/-c` is omitted: `config.yaml` → `config.yml` →
`config.json`, else a fresh `config.yaml` is created. An explicit path is honored
verbatim and chooses its encoding by extension (`.yaml`/`.yml` → YAML, otherwise
JSON), so `-c some.json` keeps full JSON behavior and is never migrated.

Do not put secrets into public examples. Real customer deployments should keep `/app/etc` private.

## Common `config.json` Fields

These fields are useful for both usque and WG mode.

| Field | Default | Applies to | Purpose |
|---|---|---|---|
| `socks.bind_address` | `127.0.0.1` in Go defaults; Docker examples usually use `0.0.0.0` | both | SOCKS5 listen address |
| `socks.port` | `1080` | both | SOCKS5 listen port |
| `socks.username` | empty | both | Optional SOCKS5 username |
| `socks.password` | empty | both | Optional SOCKS5 password |
| `socks.connection_timeout` | `30s` | both | Timeout for outbound connection setup. **L3 / WireGuard only** — L4 mode uses `l4_connection_timeout` so the two transports tune in isolation. |
| `socks.idle_timeout` | `5m` | both | Idle timeout for proxied connections. **L3 / WireGuard only** — L4 mode uses `l4_idle_timeout` (L4 streams are scarcer, so they reap sooner). |
| `logging.level` | `info` | both | `debug`, `info`, `warn`, or `error` |
| `logging.format` | `text` | both | `text` or `json` |
| `logging.socks_verbose` | `false` | both | Extra SOCKS connection diagnostics |

At `info`, lifecycle logs use clear `msg` labels (`tunnel connected`, `tunnel disconnected`, `tunnel reconnected`, `socks ready`) with details in structured fields. Tunnel reconnect steps and SOCKS drain internals are at `debug`.
| `registration.device_name` | generated or empty | usque registration | Device name used during registration |

Duration fields accept human-readable strings such as `"2s"`, `"30s"`, and `"5m"`. Legacy numeric nanosecond values are still accepted.

## Usque-Only Runtime Fields

These fields only affect `uscf proxy`. WG mode runs `uscf socks`, so it logs and ignores tunnel-only settings.

| Field | Purpose |
|---|---|
| `socks.use_ipv6` | Use the IPv6 endpoint for the MASQUE connection. |
| `socks.http2` | Use TCP+TLS+HTTP/2 for the MASQUE connection instead of QUIC+HTTP/3. CLI override: `uscf proxy --http2`. |
| `socks.l4` | Use L4 mode: tunnel each TCP flow as an HTTP/3 CONNECT stream over a **single shared QUIC connection**, bypassing the userspace netstack. Faster and lighter, but **TCP-only** (Cloudflare's MASQUE proxy endpoint refuses `connect-udp` with HTTP 403) and DNS is always resolved locally (`remote_dns` ignored). The connection model follows mihomo's/usque's validated MASQUE proxy: the connection is cached and reused for every flow, and is rebuilt when opening a request stream fails — a dead connection (Cloudflare idle eviction / path failure) or a saturated one (peer `MAX_STREAMS` reached). In that case the dial **transparently rebuilds the connection and retries once** (usque's behaviour), so the common idle-eviction case never surfaces as a failed dial. A separate **wedged-connection** guard rebuilds the connection if CONNECTs stop being answered for longer than `2 × l4_connection_timeout` — the rare case where QUIC stays alive (keepalive flows, `OpenRequestStream` keeps succeeding) but Cloudflare stops responding. By default one connection is one stable WARP egress identity, like L3, with **no in-flight stream cap** (a hard cap once locked the proxy at the ceiling instead of rebuilding). A single connection comfortably carries thousands of concurrent streams, so this single-connection path is the main line; an **optional** `l4_pool_size` (≤3) shards across a few connections purely for fault isolation, without the egress fragmentation that sank the original pool — see that row. The live open-stream count and cumulative rebuilds are logged every 30s (at `debug`, or `info` on any interval where a connection was rebuilt). Mutually exclusive with `http2`. CLI override: `uscf proxy --l4`. |
| `socks.wg` | **Experimental.** Use the in-process WireGuard transport instead of MASQUE: `uscf proxy` brings up a userspace WireGuard data plane (full tunnel, TCP+UDP) and serves it through the same SOCKS5 layer. Identity lives in a standalone `wg-account.json` (**not** `key.json`), auto-registered on first run — `key.json` is never touched. Requires `uscf proxy --experimental`; mutually exclusive with `http2` and `l4`. A reconnect supervisor keeps the session healthy with parity to L3/L4: it detects a wedged tunnel (sending but receiving nothing for ~3× `keepalive_period`) and heals it **in place** by re-pointing the peer endpoint via UAPI — so a moved WARP edge is followed without dropping the SOCKS listener — while gating new dials and resetting stranded connections during the outage. Still experimental and not the supported production runtime; `uscf wg generate` remains the stable WireGuard path. CLI override: `uscf proxy --wg --experimental`. |
| `socks.l4_half_open_timeout` | L4 only. How long a half-open TCP relay's surviving direction may stay **idle** before it is reclaimed, once the other direction has finished. It re-arms on activity, so an active/slow-but-streaming response is never cut — only a truly idle half-open flow is reaped. This keeps a finished/abandoned flow from pinning its QUIC stream (against `MAX_STREAMS`) for the full `l4_idle_timeout`. Default `30s`; `<=0` uses the default. Because the reaper only ever *shortens* the surviving direction's idle, a value greater than `l4_idle_timeout` is clamped down to it. |
| `socks.l4_connection_timeout` | L4 only. Connect / stream-open timeout for the shared QUIC connection, **separate from `connection_timeout`** so L3 and L4 tune independently. The reference MASQUE implementations (mihomo, usque) pin no explicit dial timeout; this keeps the conventional `30s`. `<=0` uses the default. |
| `socks.l4_idle_timeout` | L4 only. Idle timeout for L4 CONNECT streams, **separate from `idle_timeout`**. Default `60s` — much shorter than the L3 `idle_timeout` (`5m`) because every idle L4 stream pins a scarce QUIC `MAX_STREAMS` slot on the single shared connection, whereas an idle L3 flow is just a cheap netstack connection. The value follows the reference MASQUE implementations (usque's `60s` data-path timeout; mihomo relies on quic-go's ~30s connection idle + 30s keepalive), and the `30s` `l4_half_open_timeout` reaper handles the common one-sided case. Re-arms on activity, so an active flow is never cut. Raise it if your L4 clients hold long-idle connections (e.g. interactive SSH). `<=0` uses the default. |
| `socks.l4_pool_size` | L4 only. Number of independent shared QUIC connections to shard downstream clients across, for **fault isolation** — not capacity (one connection already carries thousands of streams). Default `1` is the single-connection main line (no sharding); raise it (capped at `3`) only for a **shared gateway** serving many distinct downstream IPs that must not all stall together. Each downstream client IP is hashed to a fixed shard, so a wedged connection disrupts only the clients hashed to it (~1/N), not every device — and because the hash is stable, **each client keeps one egress identity** (different clients spread over ≤N egress IPs), avoiding the single-client egress fragmentation that sank the original pool. Shards build lazily and only shard 0 is warmed, so an idle or single-client proxy still uses one connection. `<1` falls back to `1`. |
| `socks.l4_udp` | How L4 mode handles SOCKS UDP ASSOCIATE. `block` (default) refuses it — clients that can fall back to TCP (e.g. browsers downgrading QUIC) keep working. `direct` accepts the association but relays datagrams through a direct local socket, **bypassing WARP** (UDP egresses your real IP; only TCP is tunneled). `tunnel` (**experimental "mix" mode**) accepts the association and carries UDP over a *parallel* L3 connect-ip tunnel running alongside the L4 TCP proxy, so UDP egresses the **real WARP IP** while TCP keeps L4's per-flow QUIC speed. The L3 leg is lazy: it is not built until the first UDP datagram, has keepalive disabled so it self-evicts (~30s idle) and sleeps, and reconnects on demand — a workload that is almost entirely TCP pays nothing for it. `block_udp_443` still applies in **both** `direct` and `tunnel` modes: in `direct` it keeps QUIC off the untunneled path; in `tunnel` it prevents QUIC-in-QUIC (HTTP/3 riding the L3 tunnel) from throttling bandwidth — apps fall back to the tunneled TCP path either way. Only meaningful when `socks.l4` is on. CLI override: `uscf proxy --l4-udp tunnel`. |
| `socks.connect_port` | MASQUE endpoint port. Used as UDP port in HTTP/3 mode and TCP port in HTTP/2 mode. |
| `socks.dns` | DNS servers used by local or tunnel DNS resolver. |
| `socks.dns_timeout` | Per-DNS-query timeout. |
| `socks.remote_dns` | Resolve through the tunnel instead of local DNS. |
| `socks.no_tunnel_ipv4` / `socks.no_tunnel_ipv6` | Disable an IP family inside the MASQUE tunnel. |
| `socks.block_udp_443` | Reject outbound UDP/443 through the SOCKS proxy. |
| `socks.sni_address` | MASQUE TLS SNI override. Leave empty unless you know why it is needed. |
| `socks.keepalive_period` | QUIC keepalive (heartbeat) period — on an idle connection the client sends a PING every period so Cloudflare/quic-go (and NAT) don't idle-evict it. Only applies to HTTP/3 (QUIC) mode. Default `30s` (matching usque/mihomo); `<=0` backfills to the default, so omitting it still keeps a heartbeat. Used by **both** the L3 connect-ip tunnel and the L4 shared connection — L4 especially depends on it because it has no reconnect supervisor, so a disabled keepalive would let the shared connection self-evict every idle window. The lazy mix-mode UDP leg ignores this and is hardcoded to no keepalive (it is *meant* to self-evict and sleep). |
| `socks.mtu` | Netstack TUN (inner) MTU. Default `1280`; values up to `1400` are supported — oversized packets are clamped back to 1280 via ICMP packet-too-big. |
| `socks.initial_packet_size` | Initial QUIC packet size; seeds path MTU discovery, which probes upward from here. Default `1350` (the measured Cloudflare floor is `1242`). Only applies to HTTP/3 mode. |
| `socks.reconnect_delay` | Initial reconnect delay. |
| `socks.max_reconnect_attempts` | Pause after this many consecutive failures. `0` means unlimited retry. |

## Split Routing

Split routing only applies to usque mode.

| Field | Behavior |
|---|---|
| `socks.bypass_domain` | Exact-or-subdomain list that goes directly through the current network instead of MASQUE. |
| `socks.proxy_tcp_port` | TCP destination port allowlist for MASQUE. When non-empty, only listed TCP ports use MASQUE. |

Priority rule:

1. If `proxy_tcp_port` is non-empty, TCP routing follows the port allowlist.
2. If `proxy_tcp_port` is empty, `bypass_domain` can send matching domains direct.
3. DNS behavior still follows `remote_dns`.

Use `bypass_domain` when only a few domains should avoid the tunnel. Use `proxy_tcp_port` when only a few destination ports should use the tunnel.

## `key.json` Fields

`key.json` is usque-only identity and account state. It is created by `uscf proxy` and should normally be edited only for intentional account switching.

| Field | Purpose |
|---|---|
| `private_key` | MASQUE ECDSA private key |
| `endpoint_v4` / `endpoint_v6` | Cloudflare MASQUE HTTP/3 endpoint hosts |
| `endpoint_h2_v4` / `endpoint_h2_v6` | HTTP/2 TCP fallback endpoints (used when `socks.http2` is on). IPv4 defaults to `162.159.198.2` when empty; IPv6 must be set explicitly when `socks.http2` and `socks.use_ipv6` are both true. |
| `endpoint_pub_key` | Endpoint public key used for pinning |
| `account_mode` | `free`, `premium`, or `team` |
| `license` | Account license value returned by Cloudflare |
| `id` | Cloudflare device/account id |
| `access_token` | Token for Cloudflare API access |
| `ipv4` / `ipv6` | Assigned tunnel addresses |

If an existing `key.json` has `account_mode` set to `premium` or `team`, usque mode ignores new `--license` and `--jwt` flags. To intentionally switch account levels, set `account_mode` back to `free`, run the desired upgrade command, then restart.

## WG-Mode Files And Environment

| Item | Purpose |
|---|---|
| `wg-account.json` | Standalone WireGuard account state used by `uscf wg` commands |
| `wgcf.conf` | WireGuard profile consumed by the WG image |
| `WG_TEAM_JWT` | Optional first-bootstrap Team JWT. Ignored after deployment state exists. |
| `SOCKS_BIND_ADDRESS` | Runtime bind override used by `entrypoint-wg-socks.sh`; default `0.0.0.0` |
| `WG_INTERFACE` | WireGuard interface name; default `wgcf` |
| `WG_RUNTIME_CONFIG_PATH` | Runtime-only sanitized profile path; must end with `/wgcf.conf` when interface is `wgcf` |

The WG entrypoint strips `DNS = ...` from the runtime copy of `wgcf.conf` and injects route guard rules. The persisted `wgcf.conf` is not modified by startup.
