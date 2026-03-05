
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


## Docker Deployment

### Build Docker Image

```bash
docker build -t uscf:latest .
```

### RUN

```
docker run -d   --name uscf   --network=host   -v  /etc/uscf/:/app/etc/   --log-driver json-file   --log-opt max-size=3m   --restart on-failure  --privileged  uscf
```


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
