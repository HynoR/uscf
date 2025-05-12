# USCF (Usque)

USCF 是一个轻量级的通过 MASQUE 协议使用 Cloudflare Warp 的代理工具。它提供了简单易用的 SOCKS5 代理服务，让您能够安全地通过 Cloudflare 的网络连接互联网。

## 功能特性

- 自动注册 Cloudflare Warp 账户
- 提供 SOCKS5 代理服务
- 支持 IPv4/IPv6 双栈
- 可选的用户名/密码认证
- 可自定义 DNS 解析服务器
- Docker 容器化支持
- 简单的命令行界面

## 安装方法

### 二进制安装

1. 从 [Releases](https://github.com/HynoR/uscf/releases) 页面下载最新的适用于您操作系统的二进制文件

2. 为二进制文件添加执行权限（Linux/macOS）：
   ```bash
   chmod +x uscf
   ```

3. 将二进制文件移动到系统路径中（可选）：
   ```bash
   # Linux/macOS
   sudo mv uscf /usr/local/bin/

   # Windows (使用管理员权限的 PowerShell)
   Move-Item -Path .\uscf.exe -Destination C:\Windows\System32\
   ```

### 从源码编译

要从源代码构建 USCF，您需要安装 Go 1.18 或更高版本。

```bash
# 克隆仓库
git clone https://github.com/HynoR/uscf.git
cd uscf

# 编译
go build -o uscf .
```

## 使用方法

### 首次使用（自动注册）

首次运行时，USCF 会自动注册 Cloudflare Warp 账户并创建配置文件：

```bash
./uscf proxy --name "我的设备名称"
```

### 使用已有配置

如果您已经有配置文件，直接运行：

```bash
./uscf proxy -c config.json
```

### 查看版本信息

```bash
./uscf version
```

## Docker 部署

### 构建 Docker 镜像

```bash
docker build -t uscf:latest .
```

### 运行 Docker 容器

```bash
# 首次运行（自动注册）
docker run -d --name uscf \
  -p 2333:2333 \
  -v $(pwd)/config.json:/etc/config.json \
  uscf:latest --name "Docker设备"

# 使用现有配置
docker run -d --name uscf \
  -p 2333:2333 \
  -v $(pwd)/config.json:/etc/config.json \
  uscf:latest
```

## 配置文件说明

USCF 使用 JSON 格式的配置文件。默认配置文件路径为当前目录下的 `config.json`。

### 配置示例

```json
{
  "private_key": "BASE64编码的ECDSA私钥",
  "endpoint_v4": "162.159.198.1",
  "endpoint_v6": "2606:4700:103::1",
  "endpoint_pub_key": "PEM编码的ECDSA公钥",
  "license": "许可证密钥",
  "id": "设备唯一标识符",
  "access_token": "API访问令牌",
  "ipv4": "分配的IPv4地址",
  "ipv6": "分配的IPv6地址",
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
    "sni_address": "",
    "keepalive_period": 30000000000,
    "mtu": 1280,
    "initial_packet_size": 1242,
    "reconnect_delay": 1000000000,
    "connection_timeout": 30000000000,
    "idle_timeout": 300000000000
  },
  "registration": {
    "device_name": "设备名称"
  }
}
```

### 配置参数说明

#### 连接信息
- `private_key`: Base64 编码的 ECDSA 私钥
- `endpoint_v4`: Cloudflare Warp 服务的 IPv4 地址
- `endpoint_v6`: Cloudflare Warp 服务的 IPv6 地址
- `endpoint_pub_key`: PEM 编码的 Cloudflare Warp 服务公钥
- `license`: 应用授权密钥
- `id`: 设备唯一标识符
- `access_token`: API 访问令牌
- `ipv4`: 分配给设备的 IPv4 地址
- `ipv6`: 分配给设备的 IPv6 地址

#### SOCKS代理配置
- `bind_address`: 代理服务器绑定的地址，默认为 "0.0.0.0"（监听所有网卡）
- `port`: 代理服务器监听的端口，默认为 "1080"
- `username`: SOCKS5 认证用户名（留空表示不需要认证）
- `password`: SOCKS5 认证密码（留空表示不需要认证）
- `connect_port`: MASQUE 连接使用的端口，默认为 443
- `dns`: 在 MASQUE 隧道内使用的 DNS 服务器列表
- `dns_timeout`: DNS 查询超时时间（超时后尝试下一个服务器），单位为纳秒
- `use_ipv6`: 是否使用 IPv6 进行 MASQUE 连接
- `no_tunnel_ipv4`: 是否在 MASQUE 隧道内禁用 IPv4
- `no_tunnel_ipv6`: 是否在 MASQUE 隧道内禁用 IPv6
- `sni_address`: MASQUE 连接使用的 SNI 地址
- `keepalive_period`: MASQUE 连接的心跳周期，单位为纳秒
- `mtu`: MASQUE 连接的 MTU 值
- `initial_packet_size`: MASQUE 连接的初始包大小
- `reconnect_delay`: 重连尝试之间的延迟，单位为纳秒
- `connection_timeout`: 建立连接的超时时间，单位为纳秒
- `idle_timeout`: 空闲连接的超时时间，单位为纳秒

#### 注册信息
- `registration.device_name`: 注册的设备名称

## 重置配置

如果需要重置 SOCKS5 代理配置为默认值，可以使用以下命令：

```bash
./uscf proxy --reset-config
```

## 更多命令选项

### proxy 命令

```bash
./uscf proxy [flags]
```

可用的标志：
- `--locale string`: 注册时使用的地区设置 (默认为 "en_US")
- `--model string`: 注册时使用的设备型号 (默认为根据系统自动检测)
- `--name string`: 注册时使用的设备名称
- `--accept-tos`: 自动接受 Cloudflare 服务条款 (默认为 true)
- `--jwt string`: 团队令牌 (可选)
- `--reset-config`: 重置 SOCKS5 配置为默认值
- `-c, --config string`: 配置文件路径 (默认为 "config.json")

## 连接示例

一旦 USCF 代理服务运行起来，您可以配置应用程序使用 SOCKS5 代理：

```
代理地址: 127.0.0.1 (或您设置的 bind_address)
代理端口: 2333 (或您配置的端口)
代理类型: SOCKS5
认证信息: 如果您在配置中设置了 username 和 password，则需要提供
```

## 注意事项

1. 首次使用时自动生成的配置文件会保存在当前目录下
2. Docker 容器中的配置文件路径为 `/etc/config.json`
3. 代理服务默认监听所有网卡 (0.0.0.0)，请根据安全需求调整绑定地址
4. 如需使用用户名/密码认证，请在配置文件中设置 socks.username 和 socks.password

## 疑难解答

1. 如果连接失败，请检查您的网络环境是否能够访问 Cloudflare 服务器
2. 配置文件格式错误会导致程序无法正常启动
3. 代理端口冲突可能会导致服务无法启动，请修改配置文件中的端口设置

## 许可证

本项目基于 MIT 许可证开源。
