
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
./uscf proxy -b <bind-addr;default:127.0.0.1> -u <username;default:none> -w <password;default:none> -p <port;default:1080> -c <config.json>
```

### Use Existing Configuration

If you already have a configuration file, run directly:

```bash
./uscf proxy -c config.json
```


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

USCF uses a JSON format configuration file. The default configuration file path is `config.json` in the current directory.

### Configuration Example

After Automatic Registration, You would get a config.json like the example below, you can edit items and then restart your program to apply them.
The Config file is merge from usque's flags and configs, You can find the description of config items from usque.

```json
{
  "private_key": "BASE64 encoded ECDSA private key(Auto Generate)",
  "endpoint_v4": "(Auto Generate)",
  "endpoint_v6": "(Auto Generate)",
  "endpoint_pub_key": "PEM encoded ECDSA public key(Auto Generate)",
  "license": "License key(Auto Generate)",
  "id": "Unique device identifier(Auto Generate)",
  "access_token": "API access token(Auto Generate)",
  "ipv4": "Assigned IPv4 address(Auto Generate)",
  "ipv6": "Assigned IPv6 address(Auto Generate)",
  "socks": {
    "bind_address": "0.0.0.0",
    "port": "2333",
    "username": "",
    "password": "",
    "connect_port": 443,
    "dns": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "dns_timeout": 2000000000,
    "use_ipv6": false,
    "no_tunnel_ipv4": false,
    "no_tunnel_ipv6": false,
    "block_udp_443": false,
    "sni_address": "",
    "keepalive_period": 30000000000,
    "mtu": 1280,
    "initial_packet_size": 1242,
    "reconnect_delay": 1000000000,
    "connection_timeout": 30000000000,
    "idle_timeout": 300000000000
  },
  "registration": {
    "device_name": "Device name"
  }
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
- `--jwt string`: Team token (optional)
- `--reset-config`: Reset SOCKS5 configuration to default values
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
