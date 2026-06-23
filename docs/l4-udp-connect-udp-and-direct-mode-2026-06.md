# L4 模式的 UDP：为什么不能代理，以及 `l4_udp=direct` 直连绕过选项

日期：2026-06-23 · 分支：`feat/l4-quic-proxy`

## 问题

L4 模式（每条 TCP 流 = 一条 HTTP/3 CONNECT 流，复用同一条 QUIC 连接）为什么无法代理
UDP？能不能让它代理 / 透传 UDP？

## 一、为什么 L4 当前不能代理 UDP

L4 用的是 HTTP **`CONNECT`** 方法——它建立的是一条 TCP 字节流语义的隧道。UDP 在 MASQUE
体系里有两条可能的路：

1. **L3 / CONNECT-IP（RFC 9484）**：隧道里跑的是 IP 包，UDP 作为 IP 负载天然被携带。
   **uscf 默认（非 L4）模式已经走这条路，UDP ASSOCIATE 一直可用。** 需要隧道内 UDP 的用户
   直接用默认模式即可。
2. **CONNECT-UDP（RFC 9298）**：用扩展 CONNECT（`:protocol=connect-udp`）+ HTTP
   Datagram（RFC 9297）逐流代理 UDP。L4 的「proxy 端点」要支持它才行。

L4 走的是 Cloudflare 的 **proxy 端点**（SNI `consumer-masque-proxy.cloudflareclient.com`），
既没有 netstack/IP 层路径，也没实现 connect-udp，并且 QUIC 配置里 `EnableDatagrams:false`，
SOCKS 适配器对 L4 用 `tcpOnly`（只宣告 `CONNECT`，协商阶段直接拒绝 UDP ASSOCIATE）。

生态佐证：upstream usque 的 L4（commit `33396a8`/`8b47f8f`）也是**纯 TCP**（只用
`http.MethodConnect`）；`connect-ip-go` 明确「only support proxying of IP payloads」，没有
connect-udp 客户端；mihomo/terra 的 masque transport 用 connect-ip(L3) 承载一切包括 UDP。
**全生态没有任何实现在 CF 的 proxy 端点上跑 connect-udp。**

## 二、实测：CF 的 proxy 端点支不支持 connect-udp？

不靠推断，直接探测（`api/connectudp_probe_test.go`，注册一次性免费 WARP 账号，对 proxy
端点开启 QUIC datagram 后逐一发起请求；`RUN_CF_UDP_PROBE=1` 触发）：

| 请求（发往 proxy 端点） | 结果 |
| --- | --- |
| proxy 端点 SETTINGS | `ExtendedConnect=true`，`Datagrams=true` |
| 普通 TCP CONNECT，datagram **关**（即生产路径） | **200** ✓ |
| 普通 TCP CONNECT，datagram **开** | **200** ✓ |
| `connect-udp` RFC 9298 路径式 ×3 | **403**（稳定） |
| `connect-udp` authority 式 | **400** |

**结论：CF 的 consumer proxy 端点「认识」connect-udp（不是协议层报错，而是返回了规范的
HTTP 响应），但对正确的 RFC 9298 请求稳定回 403 Forbidden。** 也就是说能力在 CF 栈里存在，
但对 consumer（免费）账号这一档**被禁用 / 未授权**。开关 datagram 不影响 TCP CONNECT
（两种都 200），所以也不是「开了 datagram 就坏」。

含义：**对 uscf 面向的 consumer 账号，「让 UDP 走 L4」这条路当前走不通**（403）。也许带特定
entitlement 的 WARP+/Team 账号能拿到 2xx，但未验证、且超出 consumer 场景。探测器保留在仓库
（env 门控），将来 CF 若放开可一键复测。

## 三、做了什么：`socks.l4_udp` = `block` | `direct`

既然「能走 L4 走 L4」当前被 CF 挡住，就实现用户要的另一半——对走不了 L4 的 UDP 给一个
**丢弃 / 直连绕过** 的选项：

- **`block`（默认）**：`tcpOnly=true`，协商阶段拒绝 UDP ASSOCIATE。能回退 TCP 的应用
  （浏览器 QUIC→HTTP/2 降级）照常工作。= 行为与之前一致，无破坏性变更。
- **`direct`**：`tcpOnly=false`，接受 UDP ASSOCIATE，但数据报经**本地直连 socket 直接外发，
  绕过 WARP**（UDP 以真实出口 IP 走，只有 TCP 走隧道）。保住游戏 / VoIP / DNS-over-UDP /
  QUIC 这类强依赖 UDP 的应用。启动时打印明确的隐私告警。
  - `block_udp_443` 在 `direct` 下仍生效：屏蔽 UDP/443(QUIC)，逼应用回退到（被隧道保护的）
    TCP，避免 QUIC 从未加密的直连路径泄漏。

复用了既有、已测的 UDP ASSOCIATE 中继（`handleAssociate`/`directDial`/`countedConn`，与 L3
bypass UDP 同一套），新逻辑只有路由判定 `classifyL4UDP`。

启用：`uscf proxy --l4 --l4-udp direct`，或配置 `socks.l4_udp: "direct"`。

### 关键文件

- `config/config.go`：新增 `SocksConfig.L4UDP`（默认 `block`）、常量 `L4UDPBlock/L4UDPDirect`、
  `NormalizeSocksConfig` 校验（仅接受 block/direct，大小写/空白容错）。
- `cmd/l4.go`：`classifyL4UDP`（block→拒绝 / direct→直连，443 受 `block_udp_443` 抑制）；
  `prepareL4SocksRuntime` 据此设 `tcpOnly=!direct`，UDP 路由到 `directDial`，并设 `meta.udpMode`。
- `cmd/proxy.go`：`--l4-udp` flag + override（非法值告警忽略）；ready banner 增加 `l4_udp`。
- `cmd/socks.go`：socks-only 模式把非默认 `l4_udp` 列入「被忽略设置」。

### 测试

- `config/l4_udp_test.go`：归一化/默认值。
- `cmd/l4_udp_test.go`：`classifyL4UDP` 全分支（含 443 抑制、坏地址、IPv6）。
- `cmd/l4_udp_live_test.go`（env 门控）：**在线端到端**——注册账号、进程内拉起真实 L4
  `direct` 运行时、用手写 SOCKS5 UDP ASSOCIATE 客户端向 `1.1.1.1:53` 发 DNS 查询，收到 48
  字节应答 `ANCOUNT=1`。证明协商→中继 socket→直连拨号→响应封帧整条链路打通。

## 四、要真正「隧道内」的 UDP 怎么办

用 uscf **默认（L3 connect-ip）模式**——它一直能隧道 TCP+UDP。L4 是「TCP 快车道」；
`l4_udp=direct` 只是让 L4 模式在不牺牲 UDP 应用可用性的前提下，把 UDP 以直连方式放行。
（未来若想在 L4 下同时隧道 UDP，需要并行起一条 L3 隧道专跑 UDP——属于更大的特性，本次未做。）
