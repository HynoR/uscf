# 把 usque 的 L4 (QUIC 多路复用) 代理移植进 uscf — 调研 + 落地 (2026-06)

> 范围:Diniboy1123/usque issue #77（"Direct L4 proxying with QUIC"）+ 作者近一周的几次 commit。
> 结论:**可移植,已落地并实测打通**。分支 `feat/l4-quic-proxy`。
> 基准:usque upstream/main @ `0fa6da9`(含 `33396a8` L4 + `8b47f8f` 连接复用);uscf dev 基线。

---

## 一、issue #77 / 上游 L4 是什么

issue #77 来自 Cloudflare 博客 *Faster SASE proxy mode with QUIC*。核心思路:

- **旧路径(L3 / connect-ip)**:SOCKS/HTTP 客户端的 TCP 流 → 用户态 TCP/IP 栈(usque/uscf 用 gVisor netstack;CF 官方客户端用 smoltcp)做 TCP 终结 → 拆成 IP 包 → connect-ip(MASQUE CONNECT-IP, RFC 9484)隧道 → Cloudflare。每条流都要在本地跑一遍用户态 TCP 栈。
- **新路径(L4)**:客户端的 TCP 流 **直接封装进一条 QUIC stream**——用 HTTP/3(RFC 9114)的 `CONNECT` 方法,在一条共享 QUIC 连接上,**每个 TCP 连接 = 一个 HTTP/3 request stream**。绕过用户态 TCP 栈,拥塞/流控由 QUIC 原生负责。

Cloudflare 宣称的收益:绕过 smoltcp、原生 QUIC 拥塞/流控、可调参;内部测试 **上下行翻倍、延迟显著下降**。

### 上游实现(两次 commit)

| commit | 内容 |
|---|---|
| `33396a8` | `tunnel: feat: L4 SOCKS5 and HTTP Proxy modes`——新增 `api/l4proxy.go`(320 行)+ `cmd/l4_*.go`;新增 SNI `consumer-masque-proxy.cloudflareclient.com`;`l4-socks` / `l4-http-proxy` 两个子命令。 |
| `8b47f8f` | `tunnel: feat: Reuse HTTP/3 connection for L4 modes`——**这就是用户说的「QUIC 多路复用」**。修复了 #77 里 mihomo 作者 wwqgtxx 的意见:原版给每个 TCP 连接新建一条 `quic.Conn`,浪费;改成 **缓存一条 `*http3.ClientConn`,所有流复用它**,只有 `OpenRequestStream` 失败才重连一次。参考实现:mihomo `transport/masque/l4proxy.go`。 |

关键技术点:用 **stock quic-go**(`http3.Transport{}.NewClientConn` + `ClientConn.OpenRequestStream` + `RequestStream.SendRequestHeader/ReadResponse`),**不需要 fork quic-go**,也不用 connect-ip-go。请求是经典 CONNECT:`:method=CONNECT`, `:authority=ip:port`,无 body。

---

## 二、可行性判定:**绿灯**

唯一的硬门槛是 uscf 钉死的 `quic-go v0.60.0` 是否暴露 L4 需要的 API。直接查模块缓存确认:

| API | v0.60.0 位置 |
|---|---|
| `(*http3.Transport).NewClientConn` | `http3/transport.go:434` ✓ |
| `(*http3.ClientConn).OpenRequestStream` | `http3/client.go:138` ✓ |
| `(*http3.RequestStream).SendRequestHeader` | `http3/stream.go:288` ✓ |
| `(*http3.RequestStream).ReadResponse` | `http3/stream.go:320` ✓ |
| `http3.ErrCodeNoError` | ✓ |

**uscf 与 usque 用的是同一个 `quic-go v0.60.0`**——所以 L4 代码可直接移植,无需 fork、无需升级依赖、无需 connect-ip-go。

另一个关键发现(实测确认):**L4 代理端点复用现有 enrollment**。L4 用不同 SNI(`consumer-masque-proxy`)但相同的端点 IP(`162.159.198.x` 等)与相同的证书 pin(`endpoint_pub_key`)。实测 QUIC+TLS 握手通过,说明 uscf 现有注册信息直接可用。

---

## 三、与 uscf 现有 L3 架构的差异(决定集成方式)

uscf 现有 `proxy` 路径:`SOCKS listener → txthinking adapter(鉴权/路由/DNS)→ gVisor netstack DialContext → forwardingSupervisor 抽 IP 包 → connect-ip → 一条 QUIC 连接 → CF`。

L4 把中间整段(TUN/netstack/forwardingSupervisor/connect-ip)**全部拿掉**,换成 `L4Proxy.DialContext(ip:port)`。

一个天然契合点:**uscf 的 txthinking adapter 本来就在 dial 前把域名解析成 IP**(`socks_adapter.go:resolveDialAddr`)——这正好是 CF L4 CONNECT 要的(authority 必须是 IP)。所以 L4Proxy 不需要内置 DNS(上游 usque 内置了 DNS,移植时剥掉)。

| 能力 | L3 (现有) | L4 (新) |
|---|---|---|
| 传输 | connect-ip over QUIC/H3(或 H2 回退) | HTTP/3 CONNECT stream(仅 QUIC) |
| 用户态 TCP 栈 | gVisor netstack | **无** |
| TCP | ✓ | ✓ |
| **UDP** | ✓(SOCKS UDP ASSOCIATE) | **✗ 仅 TCP** |
| **隧道内 DNS**(remote_dns) | ✓ | **✗ 强制本地解析** |
| block_udp_443 | ✓ | 不适用(无 UDP) |
| bypass / proxy_tcp_port 路由 | ✓ | ✓(直连 vs L4) |
| 鉴权 / idle 超时 / 连接跟踪 | ✓ | ✓(复用同一套 runtime) |
| 空闲被 CF 清掉后重连 | demand-gated 复杂逻辑 | L4 自带:`OpenRequestStream` 失败即重连一次(更简单) |
| HTTP/2 over TCP 回退 | ✓ | 互斥(L4 必须 QUIC) |

---

## 四、uscf 落地实现(分支 `feat/l4-quic-proxy`)

### 新增/改动文件

- **`api/l4proxy.go`**(新):移植 + 改造的 `L4Proxy`。相比上游:
  - **剥掉内置 DNS**(uscf adapter 已在上游解析)。
  - **新增 `EndpointSelector`**:对接 uscf 的 custom endpoint pool(每次重连可换端点),L3 已有这能力。
  - 保留连接复用(缓存 `*http3.ClientConn`)+ `OpenRequestStream` 失败重连一次。
  - 新增 `Connect(ctx)` 预热 + `Close()` 优雅关闭。
  - `l4TCPConn` 把 QUIC stream 包成 `net.Conn`,保留 TCP 半关闭(CloseWrite=stream.Close, CloseRead=CancelRead)。
- **`api/l4proxy_test.go`**(新):半关闭/幂等 Close/重连错误分类/端点选择/校验 等单测。
- **`cmd/l4.go`**(新):`setupAndRunL4Proxy` + `prepareL4SocksRuntime` + `l4QUICConfig` + L4 TLS/端点选择。复用 uscf 全套 SOCKS 机制(鉴权、路由策略、idle 超时、缓存解析器、verbose 日志、连接跟踪),只把"隧道"换成 L4Proxy。
- **`internal/consts.go`**:加 `L4ConnectSNI`。
- **`config/config.go`**:`SocksConfig` 加 `L4 bool` (`json:"l4"`),默认 false。
- **`cmd/proxy.go`**:加 `--l4` flag;`setupAndRunSocksProxy` 在 L4 时走独立分支;`createSocksServer` 加 `tcpOnly` 参数。
- **`cmd/socks_adapter.go`**:`newTxthinkingAdapter` 加 `tcpOnly`——L4 时只 advertise `CmdConnect`,在协商阶段就拒绝 UDP ASSOCIATE。
- **`cmd/socks.go`**:`l4` 列入 socks-only 模式忽略项。

### 用法

```bash
# 配置文件 socks.l4=true,或命令行:
uscf proxy --l4 -b 127.0.0.1 -p 1080
```
启动日志:`ready ... transport=l4 endpoint=162.159.198.2:443 dns=local tunnel=up`

### 设计取舍

- **DNS 强制本地**:L4 无 netstack,没有"隧道内 DNS"。`remote_dns=true` 会被忽略并告警。CONNECT 的 authority 由 adapter 本地解析成 IP。
- **TCP-only**:UDP ASSOCIATE 在协商阶段被拒(advertise CONNECT-only),`upstreamDial` 对 UDP 再兜底拒绝。
- **tunnel 永远 up**:L4 连接惰性建立、内部自重连,没有 L3 那套 MaintainTunnel 生命周期,所以 `socksRuntime` 标记常 up,不调度 drain。
- **PMTU**:与上游不同,**保留 quic-go 的 PMTU 探测**(用 `InitialPacketSize=1350` 做种子),沿用 uscf L3 久经验证的默认,而不是上游那样钉死包大小(`DisablePathMTUDiscovery`)。

---

## 五、实测(对真实 Cloudflare)

在本机用 `proxy --l4` 自动注册免费 WARP 账号并打通:

| 目标 | 结果 |
|---|---|
| 启动 | `ready transport=l4 endpoint=162.159.198.2:443 tunnel=up`(预热握手成功 → enrollment + L4 SNI + 证书 pin 全部被接受) |
| `https://1.1.1.1/` | **HTTP 301, 0.24s** ✓ |
| `https://1.0.0.1/` | **HTTP 301, 0.22s** ✓(复用同一条 QUIC 连接) |
| `https://8.8.8.8/`(非 CF) | **HTTP 302, 0.22s** ✓ |
| `https://9.9.9.9/`(非 CF) | **HTTP 404, 0.21s** ✓ |

**对照实验**:用上游 usque 的 `l4-socks`(同 quic-go v0.60、同网络)行为一致——`1.1.1.1` 秒回,证明移植正确、与上游等价。

### 一个排查中的坑(重要,非本代码问题)

最初对 `example.com` / `github.com` 等域名目标会拿到 **504 Gateway Timeout**。排查发现:**本机有 fake-IP 透明 DNS 劫持**(Clash/mihomo 类),`dig @1.1.1.1 / @8.8.8.8 / @9.9.9.9 example.com` 全返回 `198.18.1.42`(RFC2544 保留段的 fake-IP)。即代理把 CONNECT 发到了 `198.18.x.x` 这种假 IP,CF L4 网关自然连不上 → 504。

- 用 **字面 IP**(1.1.1.1 / 8.8.8.8 / 9.9.9.9,不经 DNS)全部秒通 → **证明 L4 数据通路对任意公网目标都正常**。
- 上游 usque 同环境同样 504 → 进一步坐实是本机 DNS 环境,不是代码、也不是 CF 账号权限。
- 生产环境(无 fake-IP 劫持)下 L4 解析正常,无此问题。

---

## 六、作者近一周其它 commit 的移植评估

| commit | 评估 | 动作 |
|---|---|---|
| `33396a8` + `8b47f8f` L4 模式 + 连接复用 | 本次主线 | **已移植** |
| `21d9243` masque: Handle `PROTOCOL_VIOLATION` | CF 偶发在握手后第一次读响应时抛 QUIC `PROTOCOL_VIOLATION`;上游加了连接级 retry-once。**附带还修了一个 udpConn 泄漏**(uscf 的 `tunnel.go` 在 connect 失败时早返回、cleanup defer 还没设,导致 H3 连接失败时漏关 udpConn)。 | **已移植**(`api/masque.go`:抽出 `connectTunnelHTTP3` + 2 次重试 + `isRetryableHTTP3ConnectFailure`,每条错误路径都关 udpConn)。这是 memory 里 `port-usque-protocol-violation-retry` 那条 TODO。 |
| `10bc84c` socks5: Proper auth with UDP ASSOCIATE | uscf 早已重写了独立的 txthinking adapter,`ServeConn` 先 `Negotiate`(鉴权)再 dispatch UDP ASSOCIATE,**已天然覆盖**。 | 无需移植 |
| `2c28d85` api: set/reset WARP license key (#100) | uscf 已有 license rebind(`rebindLicenseFunc` / `applyCustomLicense` / `--license`),**已覆盖**。 | 无需移植 |
| `38df335` chore: Update dependencies | 例行升级;uscf 可按需自行 bump,与本次优化无关。 | 跳过 |
| `91d1494` ci: 32-bit Windows target | CI 矩阵,与 uscf 优化无关。 | 跳过 |
| `0fa6da9` account: tabwriter 对齐 | usque CLI 终端排版,uscf 无对应命令。 | 跳过 |

---

## 七、已知限制 / 后续可做

1. **仅 TCP**。需要 SOCKS UDP 的客户端继续用 L3。
2. **DNS 本地解析**(无隧道内 DNS,有 DNS 泄漏面)。后续可探索:CF L4 CONNECT 是否接受 **域名 authority**(让 CF 边缘解析)——若可行,既省一次本地解析又避开 fake-IP 环境。上游默认 `--local-dns`,实现里默认本地解析,暗示 CF 要 IP;待验证。
3. **吞吐基准**未做。CF 宣称翻倍,uscf 侧值得在干净网络上跑 iperf/大文件对比 L3 vs L4。
4. L4 目前只接进 `proxy` 命令;`socks`(纯本地直连)无隧道,不适用。

---

*调研 + 实现 + 实测:2026-06-23。基于源码直读 + 对真实 Cloudflare 的端到端联调。*
