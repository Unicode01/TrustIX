# TrustIX 完整项目蓝图

## 项目定位

TrustIX 是一个面向路由器部署的分布式 IX 路由交换系统。它通过根证书建立域级信任，通过签名配置日志实现可信配置传播，通过 TC/eBPF 在路由器数据面直接捕获、封装、转发、解封装和改写数据包。

TrustIX 的目标不是兼容 BGP 协议本身，而是实现一个“类 BGP 的可信 overlay 路由交换网络”：每个 IX 可以宣告本地子网、与其他 IX 建立 peer、同步路由和配置、根据策略选择下一跳，并把本地 LAN 中的机器接入跨 IX 网络。

核心目标：

- 使用根证书作为信任锚，支持域、IX、管理员、路由授权和配置签名。
- 支持任意 IX 上的可信配置修改，并快速传播到其他 IX。
- 支持 IX 之间互为 peer，进行路由同步、状态同步和数据交换。
- 支持每个 IX 绑定本地 LAN 子网，并作为该子网的网关接入 overlay。
- 数据面只使用 TC/eBPF，不使用 TUN/TAP。
- 传输层由用户配置决定，支持 UDP、QUIC、TCP、WebSocket/HTTP CONNECT 和 experimental TCP。
- 支持去程/回程策略、链路健康检查、连接级负载均衡和包级观测。
- 保留 XDP 作为高性能扩展点，但核心语义由 TC/eBPF 数据面承担。

## 核心概念

### Root

Root 是整个系统的离线信任锚，负责签发域级 CA 或信任策略。Root 不应在线参与日常配置签名。

### Domain

Domain 是一个信任域，拥有独立的配置 CA、IX 身份体系、管理员证书、路由授权和策略配置。

### IX

IX 是 TrustIX 的路由交换节点，通常部署在 Linux 路由器上。一个 IX 可以同时承担以下职责：

- 与其他 IX 建立控制面连接。
- 与其他 IX 建立数据面传输会话。
- 宣告本地 LAN prefix。
- 接收远端 prefix。
- 根据路由表和策略转发数据包。
- 管理 TC/eBPF 程序和 BPF maps。
- 参与配置日志同步和运行时状态 gossip。

### Endpoint

Endpoint 是 IX 的传输端点，可以是主动模式或被动模式。Endpoint 绑定具体传输实现，例如 UDP、QUIC、TCP、WebSocket 或 experimental TCP。

### Peer

Peer 是一个远端 IX。Peer 关系由证书身份、配置授权和 endpoint 能力共同决定。

### Prefix

Prefix 是 IX 可以宣告或接收的网段，例如 `10.0.0.0/24`、`10.0.1.0/24`。Prefix 必须有明确授权，IX 不能仅凭连接成功就宣告任意网段。

### Config Event

Config Event 是配置变更的最小可信单元。每个事件必须有签名、资源路径、版本、前序 hash、签名者身份和权限校验结果。

## 总体架构

```text
+---------------------------+
| CLI / API / UI            |
| trustixctl / admin API    |
+-------------+-------------+
              |
+-------------v-------------+
| Config Control Plane      |
| signed log / gossip       |
| snapshot / hot reload     |
+-------------+-------------+
              |
+-------------v-------------+
| Trust Control Plane       |
| mTLS / peer auth          |
| capability negotiation    |
| route sync / state gossip |
+-------------+-------------+
              |
+-------------v-------------+
| Routing Engine            |
| prefix auth / LPM         |
| next-hop / policy         |
| flow table / LB           |
+-------------+-------------+
              |
+-------------v-------------+
| eBPF Map Sync             |
| routes / peers / flows    |
| endpoints / stats / epoch |
+-------------+-------------+
              |
+-------------v-------------+
| TC/eBPF Data Plane        |
| LAN ingress / underlay    |
| encap / decap / redirect  |
| rewrite / capture / stats |
+-------------+-------------+
              |
+-------------v-------------+
| Transport Layer           |
| UDP / QUIC / TCP / WS     |
| HTTP CONNECT / exp TCP    |
+---------------------------+
```

运行组件建议：

- `trustixd`：主守护进程，负责控制面、配置传播、路由引擎、传输会话和 eBPF map 同步。
- `trustixctl`：管理 CLI，负责证书、配置、状态、抓包、诊断和调试。
- `trustix-ca`：证书和授权管理工具，负责 Root、Domain CA、Admin Cert、IX Cert、Route Authorization。
- `trustix-ebpf`：TC/eBPF 程序集合，负责数据面 fast path。

## 信任与证书模型

证书链建议：

```text
Offline Root CA
  -> Domain CA
      -> Domain Config CA
      -> Admin Cert
      -> IX Identity Cert
      -> Route Authorization Cert
```

Root CA 只作为信任锚。日常操作由 Domain Config CA、Admin Cert、IX Identity Cert 或 Route Authorization Cert 完成。

必须支持的验证：

- IX 身份验证：IX 连接 peer 时必须通过 mTLS 认证。
- 域归属验证：IX 必须属于被信任的 Domain。
- 配置签名验证：配置事件必须由有权限的证书签名。
- 路由授权验证：IX 宣告 prefix 前必须证明自己有权宣告该 prefix。
- 证书吊销验证：支持 CRL、短期证书或在线撤销列表。
- 证书轮换：支持不中断控制面传播的证书更新。

权限边界：

- Root CA 不在线签署普通配置。
- Domain Admin 可以修改全局策略、peer 授权、route policy 和信任策略。
- IX 默认只能修改自己的 endpoint、本地 LAN、运行时状态和被授权的本地 prefix。
- 一个 IX 被攻陷时，不应能修改其他 IX 的 endpoint、证书、全局策略或未授权 prefix。

## 可信配置传播

TrustIX 使用签名 append-only 配置日志实现可信配置传播。配置不能简单地用 YAML 覆盖同步，必须通过事件传播、验证和持久化。

配置事件结构：

```go
type ConfigEvent struct {
    DomainID    string
    EventID     string
    Seq         uint64
    PrevHash    string
    Resource    string
    Action      string
    Payload     []byte
    SignerID    string
    Signature   []byte
    CreatedAt   time.Time
    EffectiveAt time.Time
}
```

传播流程：

```text
用户在 IX-A 修改配置
-> IX-A 校验本地权限
-> 生成 ConfigEvent
-> 使用授权证书签名
-> 写入本地 append-only log
-> 校验并热加载
-> 推送给已连接 peers
-> 其他 IX 校验签名、权限、seq、prev_hash 和资源所有权
-> 写入本地 log
-> 应用变更
-> 继续向其他 peers gossip
```

同步协议：

```text
IX-A -> IX-B: config head seq=120 hash=abc
IX-B -> IX-A: missing 118..120
IX-A -> IX-B: ConfigEvent[118..120]
IX-B: verify -> persist -> apply -> ack
```

落后太多或新加入的 IX 使用 snapshot：

```text
snapshot:
- full desired config
- snapshot_seq
- snapshot_hash
- signer
- signature
```

配置类型必须区分：

- Desired Config：IX、endpoint、peer、route、policy、trust、authorization、LAN gateway。
- Runtime State：链路状态、RTT、丢包率、当前连接数、flow 数量、transport probe 结果。

Desired Config 必须签名、持久化、有版本、有审计。Runtime State 可以高频 gossip，但必须有 TTL，不能被当作长期配置。

冲突处理规则：

- 同一资源必须有明确 owner。
- owner 优先级高于时间戳。
- Admin 签名优先级高于 IX 自签名。
- 非 owner 修改必须拒绝，除非存在显式 delegate 授权。
- 同一资源的并发更新必须通过 generation、seq 或 compare-and-swap 语义解决。

热更新要求：

```text
validate
-> prepare runtime object
-> update BPF maps with new epoch
-> atomic switch
-> drain or migrate old flows
-> rollback on failure
```

## 路由模型

TrustIX 使用 prefix-based routing。每个 IX 维护本地路由表、远端路由表、策略表和 flow table。

路由字段建议：

```yaml
routes:
  - prefix: 10.0.1.0/24
    next_hop: ix-hongkong-1
    endpoint: hk-udp-primary
    metric: 100
    policy: default-flow-lb
```

路由引擎能力：

- 最长前缀匹配。
- prefix 授权校验。
- route import/export policy。
- metric 优先级。
- next-hop 健康检查。
- loop detection。
- route withdrawal。
- ECMP。
- 按连接数负载均衡。
- flow stickiness。
- 回程路径策略。
- 黑洞路由和拒绝路由。

连接级负载均衡：

```text
新 flow 进入
-> 提取 5-tuple 或用户定义 flow key
-> 查 flow table
-> 未命中时查询候选 endpoint
-> 选择 active_flow_count 最低或权重最优 endpoint
-> 写入 flow -> endpoint 映射
-> 后续同一 flow 固定走同一 endpoint
-> flow 超时或连接关闭后释放计数
```

不允许每个包随机选择链路，否则 TCP、QUIC 和部分应用流量会乱序严重。

## 路由器 LAN 接入模型

TrustIX 的 IX 可以作为本地 LAN 的 L3 网关。例如：

```text
IX-A LAN gateway: 10.0.0.1/24
IX-A LAN prefix:  10.0.0.0/24

IX-B LAN gateway: 10.0.1.1/24
IX-B LAN prefix:  10.0.1.0/24
```

IX-A 下的机器：

```text
IP:      10.0.0.2/24
Gateway: 10.0.0.1
```

IX-B 下的机器：

```text
IP:      10.0.1.2/24
Gateway: 10.0.1.1
```

访问路径：

```text
10.0.0.2
-> 默认网关 10.0.0.1 / IX-A
-> TC ingress 捕获 LAN 包
-> TrustIX route lookup: 10.0.1.0/24 via IX-B
-> 封装 overlay packet
-> 通过 underlay endpoint 发送到 IX-B
-> IX-B TC/eBPF 解封装
-> 转发到本地 LAN 10.0.1.2
-> 回程按 10.0.0.0/24 via IX-A 返回
```

配置示例：

```yaml
ix:
  id: ix-a
  domain: lab.local

lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  mode: routed
  manage_address: true
  manage_forwarding: true
  manage_rp_filter: true

peers:
  - id: ix-b
    allowed_prefixes:
      - 10.0.1.0/24

routes:
  - prefix: 10.0.1.0/24
    next_hop: ix-b
    policy: default
```

要求：

- `10.0.0.1/24` 是网关地址，实际宣告 prefix 是 `10.0.0.0/24`。
- IX 必须能给 LAN 接口配置网关地址。
- 如果 LAN 接口已经由系统或路由器配置好地址，可以使用 `lan.attach_mode: existing` 复用该接口；TrustIX 启动时只校验 gateway 地址存在，不新增或删除该地址。
- LAN 机器可以把 IX 作为默认网关。
- 如果 IX 不是默认网关，LAN 机器或上游路由器必须配置静态路由。
- 回程路由必须成立，否则访问会单向成功、回包丢失。
- 必须检测 prefix 冲突，例如两个 IX 同时宣告 `10.0.0.0/24`。
- 必须支持 routed mode，保留真实源 IP。
- 可以支持 NAT mode，但 NAT mode 不能作为默认语义。

## TC/eBPF 数据面

TrustIX 不使用 TUN/TAP。数据面通过 TC hook 直接挂载到 LAN 接口和 underlay 接口。

主要 hook：

```text
LAN ingress:
- 捕获本地 LAN 机器发往远端 prefix 的包。
- 进行 LPM route lookup。
- 根据 flow table 选择 next-hop 和 endpoint。
- 执行可选去程改写。
- 封装 overlay header。
- redirect 到 underlay 发送路径。

Underlay ingress:
- 识别 TrustIX overlay packet。
- 校验 overlay header、peer、epoch、anti-replay 信息。
- 解封装原始 L3 packet。
- 执行可选回程改写。
- 查本地 LAN 转发信息。
- redirect 到 LAN iface 或交给内核邻居转发。

LAN egress / Underlay egress:
- 统计、限速、mark、debug capture。
- 必要时处理 checksum、MTU、分片策略。
```

关键 BPF maps：

```text
ix_route_lpm:
  LPM trie，目标 prefix -> route entry。

ix_peer_map:
  peer id -> peer metadata、domain、trust state。

ix_endpoint_map:
  endpoint id -> transport、underlay address、ifindex、status。

ix_flow_map:
  flow key -> selected endpoint、next-hop、last_seen、flags。

ix_rewrite_map:
  policy id -> SNAT/DNAT/MAC rewrite/checksum behavior。

ix_neighbor_map:
  local LAN IP -> MAC/ifindex，或配合 bpf_redirect_neigh 使用。

ix_stats_map:
  per route / peer / endpoint / CPU counters。

ix_capture_ring:
  ringbuf/perf event，用于采样包级观测。

ix_config_epoch:
  当前配置 epoch，用于热更新和 fast path 一致性。
```

数据面必须处理：

- L2/L3/L4 header parsing。
- IPv4 checksum。
- TCP/UDP checksum 更新。
- MTU 和 overlay overhead。
- DF bit 策略。
- fragment policy。
- flow timeout。
- per-CPU counter。
- verifier 限制。
- map 更新原子性。
- 多队列、多核一致性。
- 避免封装包再次被 LAN ingress 递归处理。

邻居解析策略：

- 优先使用内核邻居表和 `bpf_redirect_neigh`。
- 在内核能力不足时，由 userspace 维护 `ix_neighbor_map`。
- userspace 负责监听 netlink neighbor event，并同步到 BPF maps。

XDP 扩展：

- XDP 不作为核心必需路径。
- XDP 可用于 underlay 早期过滤、DDoS 丢弃、快速统计、未来高速解封装。
- 所有路由语义必须先在 TC/eBPF 路径中成立。

## Overlay 封装

Overlay header 需要表达最小转发信息：

```text
magic/version
domain id hash
source ix id
destination ix id
route epoch
flow id
flags
sequence / anti-replay
payload type
optional policy id
```

封装要求：

- 能区分控制面和数据面。
- 能做基本 anti-replay。
- 能关联 peer identity。
- 能支持配置 epoch 切换。
- 能支持路径策略和 debug capture。
- 不应把完整证书或大型元数据放入每个数据包。

加密策略：

- 控制面必须使用 mTLS。
- 数据面传输默认包裹 TrustIX secure envelope，使用 X25519 派生方向密钥，当前支持 AES-256-GCM、AES-128-GCM 和 ChaCha20-Poly1305 AEAD suite，并做 sequence anti-replay。
- QUIC/TCP/TLS 等底层传输可以提供额外链路层保护，但不能替代 TrustIX packet envelope 的身份绑定、epoch 和 replay 语义。
- 是否允许未加密数据面必须由策略显式控制，默认不允许。

## 传输层

传输层由用户配置决定，不应污染路由引擎和 TC/eBPF fast path 的语义。

Transport interface：

```go
type Transport interface {
    Name() string
    Probe(ctx context.Context, peer Peer) ProbeResult
    Dial(ctx context.Context, peer Peer, tlsConf *tls.Config) (Session, error)
    Listen(ctx context.Context, ep Endpoint, tlsConf *tls.Config) (Listener, error)
}

type Session interface {
    SendPacket(pkt []byte) error
    RecvPacket() ([]byte, error)
    Close() error
    Stats() TransportStats
}
```

支持的 transport：

- UDP：主数据通道，可配自定义可靠性、加密、拥塞和探测。
- QUIC：推荐的安全通道，具备 TLS、拥塞控制、NAT 友好和连接迁移能力。
- TCP：稳定 fallback，适合 UDP 被阻断环境。
- WebSocket：适合穿透只允许 Web/HTTPS 的网络。
- HTTP CONNECT：适合代理环境和企业网络。
- experimental TCP：用户显式启用的非标准 TCP 实验通道。

用户配置示例：

```yaml
endpoints:
  - name: primary-udp
    mode: passive
    listen: 0.0.0.0:7000
    address: example.com:7000
    transport: udp

  - name: fallback-quic
    mode: passive
    listen: 0.0.0.0:7443
    address: example.com:7443
    transport: quic

  - name: fallback-tcp
    mode: passive
    listen: 0.0.0.0:8443
    address: example.com:8443
    transport: tcp

  - name: experimental
    mode: passive
    listen: 0.0.0.0:9000
    address: example.com:9000
    transport: experimental_tcp
    enabled: false
```

选择策略：

```yaml
transport_policy:
  mode: user_defined
  candidates:
    - primary-udp
    - fallback-quic
    - fallback-tcp
  load_balance: least_conn
  failover: health_based
  session_pool:
    size: 4
    strategy: flow
    warmup: true
    heartbeat:
      mode: auto
      interval: 10s
      timeout: 3s
  crypto_placement: auto
  kernel_transport:
    # auto keeps existing socket transports usable; require_kernel filters out
    # endpoints without a kernel TX/RX provider.
    mode: auto
```

`crypto_placement` 可设为 `userspace`、`auto` 或 `kernel`，当前作用于 `experimental_tcp` 和 kernel UDP/TIXU 的 secure data AEAD offload。默认 `auto` 会按 `trustix_datapath` full_datapath、`trustix_datapath_helpers` skb/GSO helper、TC/XDP/BPF direct、`trustix_crypto` AEAD device、userspace AEAD 的顺序选择最快 ready 后端；`kernel` 是严格模式，provider 或 kernel crypto 不可用时应拒绝启用；普通 UDP socket、标准 TCP、QUIC、WebSocket 和 HTTP CONNECT 仍使用 userspace secure envelope。

experimental TCP 要求：

- 默认禁用。
- 必须显式配置。
- 必须有独立统计和错误隔离。
- 不允许控制面依赖它。
- 出现异常时必须能快速回退到其他 transport。

## 控制面

控制面负责 peer 发现、mTLS、能力协商、路由同步、配置传播和状态同步。

控制面消息：

```text
hello
capabilities
authz proof
config head
config event
config snapshot
route advertise
route withdraw
state gossip
health probe
flow hint
debug request
```

能力协商：

- 支持的协议版本。
- 支持的 transport。
- 支持的 overlay header 版本。
- 支持的 eBPF feature。
- 支持的 crypto suite。
- 支持的 route policy。
- 支持的 reload 行为。

状态 gossip：

- endpoint up/down。
- RTT。
- packet loss。
- current flows。
- bytes/packets counters。
- queue/backpressure。
- current config epoch。

Runtime State 必须带 TTL。过期状态不得继续参与路由选择。

## 策略与改写

TrustIX 支持去程和回程策略，但必须限制在明确规则内，避免难以调试的隐式改写。

策略类型：

- route policy：控制 prefix import/export、metric、next-hop 选择。
- transport policy：控制 endpoint 候选、负载均衡、failover。
- rewrite policy：控制 SNAT、DNAT、MAC rewrite、TTL、mark。
- flow policy：控制 flow key、stickiness、timeout。
- capture policy：控制采样、镜像、debug packet。

rewrite 示例：

```yaml
policies:
  - name: routed-default
    type: rewrite
    mode: routed
    preserve_source: true
    rewrite_egress: false
    rewrite_return: false

  - name: nat-egress
    type: rewrite
    mode: nat
    snat_to_gateway: true
```

默认推荐 routed mode，保留真实源 IP。NAT mode 只作为兼容策略。

## 包级观测与调试

TrustIX 必须支持细粒度观测，否则 TC/eBPF 数据面很难调试。

观测能力：

- per-peer counters。
- per-endpoint counters。
- per-route counters。
- per-policy counters。
- flow table dump。
- route table dump。
- BPF map dump。
- packet capture sampling。
- drop reason。
- config epoch tracing。
- control plane event log。
- transport probe history。

drop reason 示例：

```text
NO_ROUTE
UNAUTHORIZED_PREFIX
PEER_DOWN
ENDPOINT_DOWN
FLOW_TABLE_FULL
MTU_EXCEEDED
CHECKSUM_ERROR
INVALID_OVERLAY_HEADER
REPLAY_DETECTED
CONFIG_EPOCH_MISMATCH
NEIGHBOR_UNRESOLVED
```

`trustixctl` 应提供：

```text
trustixctl status
trustixctl peers
trustixctl routes
trustixctl flows
trustixctl endpoints
trustixctl config head
trustixctl config log
trustixctl capture --peer ix-b --limit 100
trustixctl bpf maps
trustixctl doctor
```

## 安全要求

必须防御的问题：

- 未授权 IX 宣告 prefix。
- 被攻陷 IX 修改全局配置。
- 配置回滚攻击。
- 配置分叉。
- 过期 Runtime State 影响路由。
- overlay packet replay。
- peer 身份伪造。
- transport 降级攻击。
- prefix 冲突。
- flow table 资源耗尽。
- BPF map 被错误配置污染。

关键机制：

- mTLS。
- Signed Config Event。
- append-only config log。
- prev_hash chain。
- route authorization。
- resource ownership。
- config epoch。
- anti-replay。
- explicit transport policy。
- least privilege for IX cert。
- audit log。

## Linux 系统集成

TrustIX 部署在 Linux 路由器上，需要管理：

- TC qdisc 和 filter。
- eBPF object load/pin/update。
- BPF maps。
- LAN interface address。
- sysctl `net.ipv4.ip_forward`。
- rp_filter 策略。
- neighbor table。
- netlink route/address/neighbor events。
- nftables/iptables 兼容性。
- systemd service。
- crash recovery。

需要避免：

- 覆盖用户已有路由而无审计。
- 默认修改 main routing table 的关键默认路由。
- 在未授权时配置 LAN gateway。
- silent failure。
- eBPF 程序残留导致转发异常。

卸载要求：

- 能安全 detach TC programs。
- 能保留或清理 BPF pinned maps。
- 能恢复 TrustIX 管理的地址和 sysctl。
- 能输出完整变更清单。

## 配置文件总览

示例：

```yaml
domain:
  id: lab.local
  trust_roots:
    - /etc/trustix/root-ca.pem

ix:
  id: ix-shanghai-1
  cert: /etc/trustix/ix.crt
  key: /etc/trustix/ix.key
  config_log: /var/lib/trustix/config.log

lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  mode: routed
  manage_address: true
  manage_forwarding: true

endpoints:
  - name: sh-udp
    mode: passive
    listen: 0.0.0.0:7000
    address: shanghai.example.com:7000
    transport: udp
    enabled: true

  - name: sh-quic
    mode: passive
    listen: 0.0.0.0:7443
    address: shanghai.example.com:7443
    transport: quic
    enabled: true

peers:
  - id: ix-hongkong-1
    domain: lab.local
    endpoints:
      - name: hk-udp
        address: 203.0.113.10:7000
        transport: udp
      - name: hk-quic
        address: 203.0.113.10:7443
        transport: quic
    allowed_prefixes:
      - 10.0.1.0/24

routes:
  - prefix: 10.0.1.0/24
    next_hop: ix-hongkong-1
    policy: default-routed
    metric: 100

policies:
  - name: default-routed
    route_selection: longest_prefix
    load_balance: least_conn
    flow_stickiness: true
    rewrite: preserve_source

transport_policy:
  mode: user_defined
  candidates:
    - sh-udp
    - sh-quic
  crypto_placement: auto
  failover: health_based
  kernel_transport:
    mode: auto
```

## 项目边界

TrustIX 要做：

- 证书化身份和授权。
- 可信配置传播。
- TC/eBPF 原生数据面。
- 路由器 LAN gateway 接入。
- IX peer mesh。
- prefix route exchange。
- 多 transport 数据通道。
- 连接级负载均衡。
- 包级观测。
- 可审计运维。

TrustIX 不做：

- 不直接实现标准 BGP 兼容。
- 不依赖 TUN/TAP。
- 不把 Root CA 作为在线配置签名者。
- 不允许未授权 IX 宣告任意 prefix。
- 不把 Runtime State 当作长期配置。
- 不让 experimental TCP 成为控制面必需能力。

## 成功标准

TrustIX 被认为达到完整目标时，应满足：

- 多个 IX 可通过 mTLS 建立可信 peer。
- 任意授权 IX 上的配置修改可签名、传播、校验、热加载并审计。
- 每个 IX 可以宣告本地 LAN prefix，并接收远端 prefix。
- LAN 机器以 IX 为网关时，可以跨 IX 访问远端 LAN 机器。
- 所有数据包转发路径通过 TC/eBPF 完成，不依赖 TUN/TAP。
- 支持 UDP、QUIC、TCP、WebSocket/HTTP CONNECT 和 experimental TCP 的用户可配置选择。
- 支持连接级负载均衡和链路健康 failover。
- 支持 route authorization、prefix conflict detection 和配置回滚防护。
- 支持 packet capture、drop reason、flow dump、route dump 和 BPF map 诊断。
- IX 重启后可从本地签名日志和 snapshot 恢复一致配置。
