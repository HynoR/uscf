
# USCF (Modified from Usque)
Before using this tool, You need to agree the code License and CloudFlare Tos.

USCF is a 3-party experiment tool that connects to Cloudflare Warp using a unique QUIC-based protocol. This lightweight and high-performance tool provides a simple and easy-to-use SOCKS5 proxy for secure connections to Warp.

This is a tool modified from [Usque](https://github.com/Diniboy1123/usque), my branch mainly improve performace like stable memory usage or high cocurrent efficiency.

## Features

- Small, Lightweight, One-Command Automatic Deploy, Simple To Use
- Faster and more portable than using Wireguard Warp
- High Performance under connection pressure
- Docker containerization support



### Build from Source


```bash
# Clone the repository
git clone https://github.com/HynoR/uscf.git
cd uscf

# Build
go build -o uscf .
```

## Usage

### First Use (Automatic Registration)

Before you use this tool, you must accept and follow [Cloudflare TOS](https://www.cloudflare.com/application/terms/)!!!

The first time you run USCF, it will automatically register a Cloudflare Warp account and create a configuration file:

```bash
./uscf proxy -b <bind-addr;default:127.0.0.1> -u <username;default:none> -w <password;default:none> -p <port;default:1080> -c <config.json> --license <WARP+ license;optional>
```

### Use Existing Configuration

If you already have a configuration file, run directly:

```bash
./uscf proxy -c config.json
```

### SOCKS-Only Mode

If you only want USCF to expose a SOCKS5 server and let the host or container networking decide the egress path, use `socks`:

```bash
./uscf socks -c config.json -b 0.0.0.0
```

`uscf socks` only loads reusable settings from `config.json`. It does not create a TUN device, does not establish MASQUE, and does not read `key.json`.

### Standalone WireGuard Registration And Profile Generation

If you also want a standard WireGuard profile, use the `wg` command group. These commands use a separate `wg-account.json` file and do not depend on `config.json` or `key.json`.

Register a standalone WireGuard device:

```bash
./uscf wg register --accept-tos --wg-account wg-account.json --name my-device --model PC
```

Generate a WireGuard profile from the saved account:

```bash
./uscf wg generate --wg-account wg-account.json --profile wg-profile.conf
```

Runtime endpoint selection priority:
- If `custom_endpoints_v4` / `custom_endpoints_v6` has valid entries for current `socks.use_ipv6` family, USCF picks one randomly on each reconnect attempt.
- If custom list is empty or invalid, USCF falls back to `endpoint_v4` / `endpoint_v6`.

### Account Modes (`account_mode`)

USCF uses `account_mode` in `config.json` as the startup source of truth:

- `free`: trial account mode
- `premium`: personal premium mode
- `team`: team premium mode

#### Startup rules
- If config is valid (`id` + `access_token` present), USCF reuses it directly.
- If config is invalid/missing, USCF registers a new account:
  - `--license` => register `premium`
  - `--jwt` => register `team`
  - no flag => register `free`

#### Existing premium/team behavior
- If config is valid and `account_mode` is `premium` or `team`, USCF ignores `--license` and `--jwt`.
- No Cloudflare registration/license update API is sent in this case.
- When registration is required for `premium`/`team` and `--name` is not provided, USCF auto-generates a short device name:
  - format: `<m>-<host>-<id4>` (`m` is `p` or `t`)
  - `id4` is derived from account id suffix to reduce collisions when many VMs share the same hostname
  - final name is normalized and capped at 16 characters
- If `--name` is provided, it has priority, and is normalized/capped to 16 characters before registration.

#### Version switching policy
- Switching versions must go through `free` first.
- To switch from premium/team, first set `account_mode` to `free`, then run with `--license` or `--jwt` to register the new mode.
- If you stay in `premium`/`team`, repeated startup with flags will not re-register.

#### Important notes
- License bind success does not always mean immediate `warp=plus` behavior; Cloudflare side may still present `warp=on` for affected accounts.
- If you hit that behavior, create a fresh account and bind license immediately (same recommendation as wgcf docs).

#### Switching an existing free deployment to premium/team

If you already deployed a free account and want to switch the account behind `config.json` to a higher tier, use the `proxy` command against the same config file:

Upgrade free -> personal premium with a WARP+ license:

```bash
./uscf proxy -c /path/to/config.json --license YOUR-WARP-PLUS-LICENSE
```

Upgrade free -> team premium with a Zero Trust team token:

```bash
./uscf proxy -c /path/to/config.json --jwt YOUR-TEAM-JWT
```

Or drop the team token into a sibling `jwt.txt` file and let `proxy` consume it once:

```bash
printf '%s\n' 'YOUR-TEAM-JWT' > /path/to/jwt.txt
./uscf proxy -c /path/to/config.json
```

If the current config is already `premium` or `team` and you want to switch to the other mode, first change `account_mode` in `config.json` back to `free`, then run one of the commands above.

For the standalone WireGuard flow, use the same three-step pattern: upgrade the WG account, regenerate `wgcf.conf`, then restart the WireGuard SOCKS container.

```bash
# free -> premium (rebind license on the existing standalone WG account)
./uscf wg update --wg-account /app/etc/wg-account.json --license YOUR-WARP-PLUS-LICENSE
./uscf wg generate --wg-account /app/etc/wg-account.json --profile /app/etc/wgcf.conf

# free -> team (register a new team WG account and overwrite wg-account.json)
./uscf wg register --accept-tos --jwt YOUR-TEAM-JWT --wg-account /app/etc/wg-account.json
./uscf wg generate --wg-account /app/etc/wg-account.json --profile /app/etc/wgcf.conf
```

Then restart the WireGuard SOCKS container so it reconnects with the regenerated `/app/etc/wgcf.conf`.


## Docker Deployment

### Build Docker Image

```bash
docker build -t uscf:latest .
```

### Build WireGuard SOCKS Docker Image

This customer-oriented image is separate from the normal MASQUE image. It can run in two ways:

- First deployment bootstrap: if `/app/etc/config.json`, `/app/etc/wg-account.json`, and `/app/etc/wgcf.conf` are all missing, the container auto-registers a free WireGuard account, auto-generates `wg-account.json` + `wgcf.conf`, then starts `uscf socks`.
- Existing deployment: pre-populate `/app/etc/config.json` + `/app/etc/wgcf.conf` yourself. `wg-account.json` is optional in this case.

Using the image in first-deployment bootstrap mode means you accept the Cloudflare Terms of Service, because the container will automatically call `uscf wg register --accept-tos`.

Then build the special image:

```bash
docker build -f Dockerfile.wg-socks -t uscf:wg-socks .
```

### RUN

```
docker run -d   --name uscf   --network=host   -v  /etc/uscf/:/app/etc/   --log-driver json-file   --log-opt max-size=3m   --restart on-failure  --privileged  uscf
```

### RUN WireGuard SOCKS Image

This variant always derives its WireGuard runtime config from `/app/etc/wgcf.conf`, brings that runtime copy up with `wg-quick`, and then starts `uscf socks -c /app/etc/config.json -b 0.0.0.0`.

For container mode, the image keeps the persisted `/app/etc/wgcf.conf` unchanged but creates a runtime-only sanitized copy before calling `wg-quick up`. Any `DNS = ...` line in `wgcf.conf` is ignored in this image, so the container does not try to rewrite `/etc/resolv.conf`.
The runtime copy also injects `PostUp` / `PostDown` route-guard rules so replies to Docker port-mapped SOCKS connections can still leave through the container's original main route after WireGuard becomes the default route.
Run this image with `--privileged`. `wg-quick` configures full-tunnel policy routing for the generated `wgcf.conf`, and container deployments that omit `--privileged` can fail when WireGuard tries to set `net.ipv4.conf.all.src_valid_mark=1`.

#### First deployment with auto bootstrap

Mount a writable directory. Bootstrap is triggered only when `/app/etc/config.json`, `/app/etc/wg-account.json`, and `/app/etc/wgcf.conf` are all missing; unrelated files in `/app/etc` do not disable it.

```bash
docker run -d \
  --name uscf-wg \
  --privileged \
  -p 1080:1080 \
  -v /host/uscf:/app/etc \
  --restart unless-stopped \
  uscf:wg-socks
```

Generated on first successful startup:
- `/app/etc/config.json`
- `/app/etc/wg-account.json`
- `/app/etc/wgcf.conf`

The generated `config.json` uses anonymous SOCKS by default. If you want runtime-only overrides, you can append normal `uscf socks` flags to `docker run`, for example:

```bash
docker run -d \
  --name uscf-wg \
  --privileged \
  -p 1081:1081 \
  -v /host/uscf:/app/etc \
  --restart unless-stopped \
  uscf:wg-socks -p 1081 -u demo -w secret
```

These flags only affect the running process and do not rewrite `config.json`.

#### Existing deployment with pre-generated files

If `config.json` and `wgcf.conf` already exist, the container skips registration and profile generation and starts directly:

```bash
docker run -d \
  --name uscf-wg \
  --privileged \
  -p 1080:1080 \
  -v /host/uscf/config.json:/app/etc/config.json:ro \
  -v /host/uscf/wgcf.conf:/app/etc/wgcf.conf:ro \
  --restart unless-stopped \
  uscf:wg-socks
```

Expected existing-deployment layout:
- `/host/uscf/config.json -> /app/etc/config.json`
- `/host/uscf/wgcf.conf -> /app/etc/wgcf.conf`
- `/host/uscf/wg-account.json -> /app/etc/wg-account.json` (optional)

Behavior differences from the normal image:
- Normal image runs `uscf proxy` and uses MASQUE/TUN.
- WireGuard SOCKS image sanitizes `/app/etc/wgcf.conf` into a runtime copy, runs `wg-quick up` on that copy, and then starts `uscf socks`.
- In `socks` mode, tunnel-specific settings such as MASQUE identity, `bypass_domain`, `proxy_tcp_port`, `block_udp_443`, and remote/custom DNS options are ignored.
- `wgcf.conf` may still contain `DNS = ...` for generic WireGuard compatibility, but this special image strips those lines from the runtime copy before `wg-quick up`, so container DNS is left untouched.
- This image uses `uscf + wg-quick`; it does not embed `wgcf + microsocks`, and it does not support the old `HOST` / `PORT` / `USER` / `PASSWORD` environment-variable interface.
- Re-registration, license upgrade, or profile regeneration is done explicitly with `uscf wg register` / `uscf wg update` / `uscf wg generate`, not by entrypoint environment variables.
- Connectivity recovery is handled by Docker `HEALTHCHECK` and your orchestrator restart policy; the entrypoint does not run an internal `curl` retry loop.
- The built-in route guard requires a detectable pre-WireGuard IPv4 default route and source IPv4 address. If the container is IPv6-only or has unusual routing that hides them, startup will fail before `wg-quick up`.
- Startup state rules are strict:
  - all three of `config.json`, `wg-account.json`, `wgcf.conf` missing => bootstrap
  - `config.json` + `wgcf.conf` present => start existing deployment
  - any other partial combination => fail fast instead of auto-repair


## Configuration File Description

USCF now uses two JSON files in the same directory:

- `config.json`: shared/reusable runtime settings (`socks`, `logging`, `registration`, `custom_endpoints_*`)
- `key.json`: node-specific Cloudflare/MASQUE identity fields (`private_key`, `endpoint_*`, `id`, `access_token`, etc.)

The default path passed by `-c/--config` is still `config.json`. `key.json` is always resolved in the same directory.

### Configuration Example

After automatic registration, you will get `config.json` + `key.json` in the same directory.
You can edit items and restart your program to apply them.
The Config file is merge from usque's flags and configs, You can find the description of config items from usque.

Time options (`dns_timeout`, `keepalive_period`, `reconnect_delay`, `connection_timeout`, `idle_timeout`) use human-readable strings: unit suffixes are `ns`, `us`/`µs`, `ms`, `s`, `m`, `h` (e.g. `"2s"`, `"5m"`, `"1h30m"`). Legacy configs with numeric nanosecond values are still accepted.

Logging options are configured in `logging`:
- `level`: `debug`, `info`, `warn`, `error` (default: `info`)
- `format`: `text`, `json` (default: `text`)
- `socks_verbose`: whether to emit SOCKS connection-level diagnostics (default: `false`)

Reconnect guard option:
- `socks.max_reconnect_attempts`: maximum consecutive reconnect attempts before pausing retries for manual intervention. `0` means unlimited retry (default).

Bypass domain option:
- `socks.bypass_domain`: domain allowlist for direct network egress. Matching rule is exact-or-subdomain (`example.com` matches both `example.com` and `a.example.com`).
- When a destination domain matches this list, traffic bypasses MASQUE tunnel and uses the current host network directly.

Proxy TCP port option:
- `socks.proxy_tcp_port`: TCP destination port allowlist for MASQUE tunnel egress. Example: `[80, 443]` means only TCP/80 and TCP/443 use TUN; TCP/1001, TCP/992, TCP/1102 go out directly.
- When `socks.proxy_tcp_port` is non-empty, it takes priority over `socks.bypass_domain` for TCP routing decisions. DNS behavior still follows `socks.remote_dns`.

`config.json`:

```json
{
  "custom_endpoints_v4": [],
  "custom_endpoints_v6": [],
  "socks": {
    "bind_address": "0.0.0.0",
    "port": "2333",
    "username": "",
    "password": "",
    "bypass_domain": [],
    "proxy_tcp_port": [],
    "connect_port": 443,
    "dns": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "dns_timeout": "2s",
    "use_ipv6": false,
    "no_tunnel_ipv4": false,
    "no_tunnel_ipv6": false,
    "block_udp_443": true,
    "sni_address": "",
    "keepalive_period": "30s",
    "mtu": 1280,
    "initial_packet_size": 1242,
    "reconnect_delay": "1s",
    "max_reconnect_attempts": 0,
    "connection_timeout": "30s",
    "idle_timeout": "5m",
    "self_check": false
  },
  "logging": {
    "level": "info",
    "format": "text",
    "socks_verbose": false
  },
  "registration": {
    "device_name": "Device name"
  }
}
```

`key.json`:

```json
{
  "private_key": "BASE64 encoded ECDSA private key(Auto Generate)",
  "endpoint_v4": "(Auto Generate)",
  "endpoint_v6": "(Auto Generate)",
  "endpoint_pub_key": "PEM encoded ECDSA public key(Auto Generate)",
  "account_mode": "free|premium|team",
  "license": "License key(Auto Generate)",
  "id": "Unique device identifier(Auto Generate)",
  "access_token": "API access token(Auto Generate)",
  "ipv4": "Assigned IPv4 address(Auto Generate)",
  "ipv6": "Assigned IPv6 address(Auto Generate)"
}
```



## Reset Configuration

If you need to reset the SOCKS5 proxy configuration to default values, you can use the following command:

```bash
./uscf proxy --reset-config
```

## More Command Options

### proxy Command

```bash
./uscf proxy [flags]
```

Available flags:
- `--locale string`: Locale used during registration (default "en_US")
- `--model string`: Device model used during registration (defaults to automatic detection based on the system)
- `--name string`: Device name used during registration
- `--accept-tos`: Automatically accept Cloudflare Terms of Service (default true)
- `--jwt string`: Team token; used when registration is required (optional)
- `--license string`: Personal premium license; used when registration is required (optional)
- `--reset-config`: Reset SOCKS5 configuration to default values
- `--use-ipv6`: Override `socks.use_ipv6` in config file for current startup
- `-c, --config string`: Configuration file path (default "config.json")

### socks Command

```bash
./uscf socks [flags]
```

Available flags:
- `-c, --config string`: Configuration file path (default "config.json")
- `-b, --bind-address string`: Bind address for the SOCKS5 listener
- `-p, --port string`: Port for the SOCKS5 listener
- `-u, --username string`: Username for SOCKS5 authentication
- `-w, --password string`: Password for SOCKS5 authentication

Notes:
- `socks` reads only `config.json` public settings and ignores `key.json`.
- `socks` does not create TUN or MASQUE connections; outbound traffic follows the current host or container routing table.
- Startup logs will list ignored tunnel-specific settings if they are present in the config.

### wg register Command

```bash
./uscf wg register [flags]
```

Available flags:
- `--wg-account string`: WireGuard account file path (default "wg-account.json")
- `--name string`: Device name shown in the 1.1.1.1 app
- `--model string`: Device model shown in the 1.1.1.1 app (default "PC")
- `--key string`: Existing base64 WireGuard private key (optional)
- `--license string`: WARP+ license key; registers a new premium standalone WG account
- `--jwt string`: Team token; registers a new team standalone WG account
- `--accept-tos`: Accept Cloudflare Terms of Service non-interactively

Notes:
- `wg register --license` creates a new standalone WG account and immediately rebinds it to the target WARP+ license.
- `wg register --jwt` creates a new standalone team WG account.

### wg generate Command

```bash
./uscf wg generate [flags]
```

Available flags:
- `--wg-account string`: WireGuard account file path (default "wg-account.json")
- `--profile string`: Output WireGuard profile path (default "wg-profile.conf")

### wg update Command

```bash
./uscf wg update [flags]
```

Available flags:
- `--wg-account string`: WireGuard account file path (default "wg-account.json")
- `--license string`: WARP+ license key to bind to the existing standalone WG account

Notes:
- `wg update` only supports WARP+ license rebind on an existing standalone WG account.
- `wg update` does not accept `--jwt`; team mode is created through `wg register --jwt`.

## Connection Example

Once the USCF proxy service is running, you can configure applications to use the SOCKS5 proxy:

```
Proxy Address: 127.0.0.1 (or the bind_address you set)
Proxy Port: 2333 (or the port you configured)
Proxy Type: SOCKS5
Authentication Information: If you set username and password in the configuration, you need to provide them
```

## Disclaimer

Please do NOT use this tool for abuse. At the end of the day you hurt Cloudflare, which is probably unfair as you get this stuff even for free, secondly you will most likely get this tool sanctioned and ruin the fun for everyone.

The tool mimics certain properties of the official clients, those are mostly done for stability and compatibility reasons. I never intended to make this tool indistinguishable from the official clients. That means if they want to detect this tool, they can. I am not responsible for any consequences that may arise from using this tool. That is absolutely your own responsibility. I am not responsible for any damage that may occur to your system or your network. This tool is provided as is without any guarantees. Use at your own risk.


## License

This project is open source under the MIT License.
