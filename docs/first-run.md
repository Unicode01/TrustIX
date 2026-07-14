# TrustIX 第一版运行方式

当前第一版提供本地可运行的后端骨架：

- 读取 YAML/JSON desired config。
- 使用 `trustix-ca` 生成 Root、Domain、Config、Admin、IX 和 Route Authorization 证书。
- 校验 IX、LAN、endpoint、peer、route、transport policy 和本地 route authorization。
- 支持 domain 级 trust resource：`/domain/trust` 会进入 signed config log，并通过 peer config sync 自动传播。`trust.revoked_cert_fingerprints`、`trust.trust_roots_pem` 和 `trust.admin_policy` 仍可作为本地启动初始策略；一旦链上存在 `/domain/trust`，后续按链上 trust epoch/effective seq 收敛。
- 首次启动会写入 domain common genesis config event；后续 `config apply` 会使用 IX 私钥签名 `/ix/<ix>/desired` 事件并写入本地 append-only config log。第一次 apply 会先记录当前 runtime desired 作为 rollback baseline，再记录新 desired。
- 应用路由表和 dataplane snapshot。
- 启动本地管理 API；可选 `management.host_api` 会额外在 LAN gateway 或指定地址上启动主机侧管理入口，给当前 IX 下的主机访问本 IX 面板/API。多 LAN 配置下未显式指定 `listen` 时会选择第一个配置了 gateway 的 LAN。
- 通过 peer `control_api` 使用 mTLS 拉取并校验远端 LAN prefix / endpoint 广告。
- 支持 `bootstrap.peers`：新 IX 可以只配置自己的 endpoint 和一个 bootstrap control API，启动后推送自身 signed advertisement、拉取成员列表、学习其他 IX 并热更新路由。第一版使用 domain admission：远端 IX 的 membership advertisement 必须匹配 `/domain/admissions/<ix>` 批准事件，未批准但已通过证书链、签名、route authorization 和 endpoint 基础校验的远端 IX 会进入 pending admission 队列，不进入动态成员表或路由表，管理员可再基于已观测广告一键批准。pending 队列会落盘到 `<data-dir>/pending-members.json`，daemon 重启后会重新校验基础真实性、当前 trust/admission 状态和 24h TTL，再恢复仍然有效的待批准广告。
- 支持 `route_policy`：接收方可用 `import_prefixes` 限制动态路由导入，用 `dynamic_metric` 调整动态 route metric，用 `import_transit_routes`/`transit_forwarding` 控制是否学习/承载二跳 IX transit；本机可用 `export_prefixes` 限制对外广告哪些 LAN prefix。静态 route 支持 `owner` 和 `next_hop` 分离，`owner` 表示前缀拥有/授权 IX，`next_hop` 表示实际下一跳 IX；未配置 `owner` 时默认 `owner=next_hop`。
- 支持 `transport_policy.mtu` 和 `transport_policy.fragment_policy: drop`。Linux dataplane 会把 packet policy 同步到 TC/eBPF，在 route-hit capture 前直接丢弃超 MTU 或 IPv4 fragment；userspace data path 仍保留同样的 fail-closed 校验作为 noop/fallback 防线。
- 提供可收发包的 UDP、QUIC、TCP、WebSocket 和 HTTP CONNECT 数据面 transport 实现。
- daemon 注册的 UDP/QUIC/TCP/WebSocket/HTTP CONNECT transport 默认包裹 TrustIX secure transport：支持 `AES-256-GCM-X25519`、`AES-128-GCM-X25519` 和 `CHACHA20-POLY1305-X25519`，默认只启用 `AES-256-GCM-X25519`，可用 `transport_policy.crypto_suites` 配置本机允许的套件。TrustIX hello 会交换 suite bitmap 并在共同套件中优先选择快路径友好的 `AES-128-GCM-X25519`，data packet payload 做 AEAD 和 sequence anti-replay。`transport_policy.encryption` 默认 `secure`，也支持 `plaintext`、`send_encrypted` 和 `receive_encrypted`，用于按方向关闭 data packet envelope；TrustIX hello/IX 证书认证仍保留。endpoint 可用 `security.encryption` 覆盖全局策略并随成员广告传播；拨出端会按对端 endpoint 声明自动使用互补方向，例如对端声明 `receive_encrypted` 时本端 session 使用 `send_encrypted`。endpoint 未声明 `security.encryption` 时按全局 `transport_policy.encryption` 处理。需要避免双层加密时，可使用 TLS-only data mode：`transport_policy.encryption: plaintext` 或 endpoint `security.encryption: plaintext`，同时把对应 endpoint `security.link_tls: required`；该模式只允许 TCP/WebSocket/HTTP CONNECT/QUIC 这类支持 link TLS 的 transport，session 建立后若实际没有 LinkTLS 会 fail-closed。`transport_policy.crypto_key_source` 支持 `auto`、`trustix_x25519` 和 `tls_exporter`；默认 `auto` 会在底层 transport 有 IX 证书 mTLS/TLS exporter 时用 TLS exporter 派生 TrustIX data key，否则退回 TrustIX X25519 transcript。第一版仍保留 TrustIX secure envelope，不生成标准 TLS record。
- `transport_policy.kernel_transport.mode` 支持 `auto`、`prefer_kernel`、`require_kernel` 和 `disabled`。当前真正具备内核 TX/RX plane 的协议是 TIX-TCP (`tix_tcp`) 和 UDP/TIXU：XDP/AF_XDP 负责固定 TrustIX frame 收发，secure 握手留在 daemon；TIX-TCP 与 UDP/TIXU 的 AES-256/AES-128-GCM data AEAD 都可在 provider 就绪时走 kernel crypto，否则按策略回到 userspace。ChaCha20-Poly1305 目前仍是 userspace-only，状态 schema 会明确标为 unsupported，而不是伪装成内核 offload。`gre`/`ipip` 第一版使用 Linux netlink 创建 kernel tunnel netdev，TrustIX packet 走隧道内 UDP carrier，endpoint 必须显式提供 `local`、`remote`、`local_carrier`、`remote_carrier` 和可选 `port`，不提供 raw-socket fallback。`QUIC/TCP/WebSocket/HTTP CONNECT` 仍是 userspace socket transport；标准 QUIC 的 TLS、ACK、recovery、拥塞控制和连接迁移不会伪装成 eBPF 内核实现。设置 `require_kernel` 时，没有 kernel transport provider 的 endpoint 会被过滤或拒绝。
- 传输层 TLS 证书可与 TrustIX IX 身份证书分离。默认 `transport_policy.tls_identity.mode: ix_cert` 会复用 `ix.cert`/`ix.key` 做底层 TLS；`custom_cert` 可改用 IP SAN 证书、公网证书或独立私有 CA 证书做 TCP/WebSocket/HTTP CONNECT/QUIC 链路 TLS 和 TLS exporter。secure overlay 仍单独使用 IX 证书签 TrustIX hello，因此公网/IP 证书不会替代 IX 身份认证。
- TIX-TCP 的共享帧格式、secure transport 接入、crypto placement 配置、secure-to-provider crypto offload 协议和 Linux AF_XDP/XDP fast path 已经接入。配置、API 和运行时统一使用 `tix_tcp`，旧协议名会被拒绝。raw socket 只保留为显式调试 fallback，不作为快路径；默认必须等待 AF_XDP provider 可用才会把 endpoint 判定为 `reinject=true`。AF_XDP attach/bind 会优先协商 native XDP + zero-copy，失败后自动退到 native copy，再退到 SKB copy；`trustixctl datapath` 会暴露 `xdp_attach_mode`、`af_xdp_bind_mode`、`zerocopy_enabled` 和 fallback reason。空配置的生产默认固定为 `crypto_placement: userspace`；显式设置 `crypto_placement: auto` 时才会优先选择当前主机报告 ready 的最快受支持路径，降级顺序为 `trustix_datapath` full_datapath、`trustix_datapath_helpers` skb/GSO helper、TC/XDP/BPF direct 或 BPF_PROG_RUN crypto、`trustix_crypto` AEAD device、userspace AEAD；显式 `userspace` 强制 daemon AEAD，显式 `kernel` 仍 fail-closed。fast-path TX 会直接在 AF_XDP UMEM TX frame 中构建 Ethernet/IPv4/TCP/TIXT 包，不再先分配中间 IPv4 packet；多队列发送按 `FlowID` 固定 TX queue，缺少 flow id 时按 underlay IPv4/TCP tuple 固定 queue，避免同一 flow 被轮询打散；TX frame/ring 短时压力会先 reclaim completion 并在有界窗口内重试。当目标内核具备 BPF crypto kfunc 且加载可选 `trustix_crypto` 后，`kernel` placement 会把 secure 握手派生出的真实 flow key 安装进 provider kptr ctx slot 和 flow map，再由 BPF_PROG_RUN XDP packet seal 程序把 secure envelope/ciphertext/tag 写回同一 UMEM frame，最后发布 TX descriptor；RX attached XDP 会优先 open/replay/drop，启动期 recv ctx 尚未安装时会把密文 frame 转交 AF_XDP/Go 侧短重试，避免 no-context 竞态丢第一批包。send 方向会拒绝重复或倒退 sequence，避免同一 flow/epoch 下 nonce 复用。provider 不可用时会拒绝显式 `kernel`，`auto` 会退到可认证的下一档而不会降级成未认证明文。临时 key/IV clone、Go-side encoded entry 和 command slot 会在安装调用返回后清零；key material 不写入状态文件、日志或 API。如果 offload 成功，secure session 会释放 userspace AEAD/IV 引用。
- The kernel crypto probe reports `selftest_attempted/selftest_passed`, loads an embedded ELF/CO-RE verifier selftest for syscall ctx setup plus XDP/TC encrypt/decrypt kfunc paths, and loads the provider-side kptr ctx-map object. A synthetic AEAD-GCM `bpf_crypto_ctx_create` plus encrypt/decrypt roundtrip runtime probe is reported separately; frame seal/open counters prove whether real traffic is using the provider.
- Linux dataplane 下，TC/eBPF route-hit 会进入 userspace data path：daemon 查路由、规范化 veth/TC 捕获到的 IPv4/TCP/UDP checksum、复用 secure transport session 加密发送。TC route-hit capture 默认会 pull 并上送最多 16KiB packet sample，用来覆盖常见 4KiB TCP payload/GSO 测试包；超过该窗口的包仍会 fail-closed，避免截断包被错误转发。对端解密后如果目的地址属于本地 LAN prefix 就通过 LAN packet reinject 送回本地 LAN；否则在 `route_policy.transit_forwarding` 允许时按本机路由表递减 IPv4 TTL 后继续转发到下一跳 IX，用于显式 transit 路由。
- 通过 `trustixctl` 查询状态、peer、route、route-policy、endpoint、config log、capture、datapath、BPF 边界和 doctor。

先生成示例证书：

```powershell
go run ./cmd/trustix-ca quickstart -out certs -domain lab.local -ix ix-a,ix-b
```

启动默认实验节点：

```powershell
go run ./cmd/trustixd
```

默认配置文件是 `configs/lab-a.yaml`，默认 API 地址是 `127.0.0.1:8787`，默认数据目录是 `.trustix`。
默认 peer mTLS API 地址是 `127.0.0.1:9443`。
默认 dataplane 是 `noop`，用于普通开发环境。Linux 测试机上可以显式启用系统集成 dataplane：

```powershell
go run ./cmd/trustixd -dataplane linux
```

设备认证接入模式：

IX 可以用自己的 IX CA 证书签发子设备证书。设备用该证书连接 IX 的数据 endpoint，IX 会从 `lan.device_access.address_pool` 分配一个 LAN 段内 `/32` 地址，并把该 `/32` 加入本机 runtime route 和 signed advertisement。这样同 IX 下的设备、LAN 主机，以及通过 membership 学到该 `/32` 的其他 IX 都可以把回程包送回设备的反向 data session。

IX 侧配置示例：

```yaml
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24
  device_access:
    enabled: true
    address_pool: 10.0.0.240/28
    lease_ttl: 24h
```

多 LAN 配置：

顶层 `lan:` 是 primary LAN，Linux dataplane 的 TC/eBPF attach、gateway 地址管理、proxy ARP 和 NAT gateway 默认使用 primary LAN。需要把多个本地可信网段放进同一个 IX 时，可以新增 `lans:`；每个条目需要唯一 `id`，`type` 支持 `local` 和 `trusted_public`。`trusted_public` 表示由本 IX 管控或信任的公网/半公网三层网段，不表示任意 WAN underlay。`lans:` 中的前缀会进入本机 signed advertisement、route policy export、runtime local route、本地 LAN 目的判断和管理 host API gateway 自动选择。

```yaml
lan:
  iface: br-lan
  gateway: 10.0.0.1/24
  advertise:
    - 10.0.0.0/24

lans:
  - id: public-lan
    type: trusted_public
    iface: br-public
    gateway: 203.0.113.1/29
    advertise:
      - 203.0.113.0/29
    attach_mode: existing
    manage_address: false
```

当前阶段多 LAN 已经覆盖控制面和 daemon runtime；Linux TC/eBPF attach 仍只挂 primary LAN。额外 LAN 如果要直接捕获/回注数据，需要通过系统路由/桥接把流量送到 primary LAN 路径，或等待后续多接口 TC attach。

签发设备证书：

```bash
go run ./cmd/trustix-ca device issue -out certs -domain lab.local -ix ix-a -device laptop-1
```

Linux 设备端可以直接用 flags 接入：

```bash
sudo ./trustix-device \
  -domain lab.local \
  -ix ix-a \
  -endpoint ix-a.example.com:7000 \
  -transport udp \
  -cert certs/ix-a-laptop-1.crt \
  -key certs/ix-a-laptop-1.key \
  -ca certs/root-ca.pem \
  -ca certs/domain-ca.pem \
  -route 10.0.0.0/24
```

也可以写成配置文件：

```yaml
domain: lab.local
ix: ix-a
endpoint:
  name: ix-a-udp
  address: ix-a.example.com:7000
  transport: udp
cert: certs/ix-a-laptop-1.crt
key: certs/ix-a-laptop-1.key
trust_roots:
  - certs/root-ca.pem
  - certs/domain-ca.pem
encryption: secure
crypto_key_source: auto
interface:
  name: trustix0
  mtu: 1400
  routes:
    - 10.0.0.0/24
stats_every: 30s
```

```bash
sudo ./trustix-device -config device.yaml
```

`trustix-device` 会创建 TUN 接口（默认 `trustix0`），收到 IX 下发的租约后配置 `/32` 地址，并按 `-route` 或 `interface.routes` 添加本机路由。路由可重复，按需写入要走 TrustIX 的 LAN/远端 LAN CIDR；需要全隧道时可显式写 `0.0.0.0/0`。IX 侧 Linux dataplane 会为活跃 device `/32` 在 LAN iface 上同步 proxy ARP，并开启该接口的 `proxy_arp`/`proxy_arp_pvlan`，所以 LAN 主机不需要手动添加到设备地址的静态路由；租约消失或 dataplane cleanup 时会删除对应 proxy ARP entry 并恢复 sysctl。当前设备端 TUN 数据面只在 Linux 实现；Windows 客户端需要后续接 Wintun/路由配置层。数据 transport 可选 `udp`、`tcp`、`quic`、`websocket`、`http_connect` 和 `tix_tcp` userspace/compat 路径；新设备接入不依赖内核模块。

设备接入控制面：

```bash
trustixctl device-access
trustixctl device-access show laptop-1
trustixctl device-access revoke laptop-1
trustixctl device-access revoke -fingerprint <device-cert-sha256>
```

`GET /v1/device-access` 会列出当前租约、在线状态、设备证书指纹、endpoint、transport、加密模式和 session stats。`POST /v1/device-access/revoke` 会把设备证书 SHA256 指纹写入 domain trust revocation，立即断开匹配的设备 session，删除对应 lease/runtime route/proxy ARP，并刷新本机 advertisement。直接使用 `trustixctl trust revoke <device-cert-fingerprint>` 也会触发同样的在线设备踢出逻辑。

Linux dataplane 当前会：

- 通过 netlink 管理 link/address/TC qdisc，不依赖 shell 调用 `ip` 或 `tc`。
- 检测 bpffs 是否可用。
- 给 LAN iface 配置 gateway 地址。
- `lan.attach_mode: existing` 可直接复用已有物理口/桥口作为 LAN 入口；此模式要求 `lan.gateway` 已经存在于该接口上，并强制 `manage_address: false`，TrustIX 只挂 TC/eBPF、可选 forwarding/rp_filter，不接管接口地址。
- 开启 `net.ipv4.ip_forward`。
- 按配置关闭 LAN iface 的 `rp_filter`。
- 为活跃 `lan.device_access` 租约同步 LAN iface proxy ARP，让同网段主机直接 ARP 设备 `/32` 时由 IX 应答。
- 准备 TC `clsact` qdisc。
- 加载并挂载 TC `SchedCLS` eBPF 程序到 ingress/egress。
- 维护 eBPF array stats map，`trustixctl bpf maps` 会返回 `tc_ingress_packets` 和 `tc_egress_packets`。
- 维护 IPv4 route LPM map，把 desired routes 同步到 `ix_route_lpm`。
- 在 LAN ingress 快路径解析 Ethernet/IPv4 目标地址并执行 LPM 查表，`trustixctl bpf maps` 会返回 route hit/miss 计数。
- route hit 时通过 `ix_capture_events` perf event map 把 packet metadata 和最多 16KiB 的 packet sample 送到 daemon，`trustixctl capture` 可查看最近 capture 事件；daemon 只转发未截断的 capture sample，超过窗口的包会按 fail-closed 处理。
- route hit 原包会在 TC ingress fail-closed drop，避免本机普通路由旁路转发明文或产生重复包。
- daemon 订阅 route-hit capture，按 LPM route 选择 peer endpoint，并通过 secure transport 发送。静态 route 的 `owner` 用于前缀授权和冲突仲裁，`next_hop` 用于实际 transport 选择；例如 `owner: ix-c`、`next_hop: ix-b` 会把目的前缀属于 ix-c 的包先发给 ix-b。
- 当 route 没有显式 `endpoint` 时，daemon 会按 route policy 的 `flow_stickiness` 和 `load_balance: least_conn` 在 peer endpoints 中选择；`trustixctl flows` 会显示当前 flow 到 endpoint 的绑定。`transport_policy.session_pool.size` 可为同一个 `(peer, endpoint, transport, address, encryption)` 建多条底层 session；`session_pool.strategy: flow`/`five_tuple` 会按 IPv4 五元组哈希固定到池内连接，`strategy: packet`/`round_robin` 会按包轮询，`warmup: true` 会在首次拨通后预拨满池。`session_pool.heartbeat.mode` 支持 `auto`/`enabled`/`disabled`，默认 `auto` 只在 `size > 1` 时启用，默认 `interval: 10s`、`timeout: 3s`；心跳帧走现有 secure transport，不会注入 LAN。默认 `size: 0/1` 表示单连接。
- `transport_policy.failover: health_based` 会启用 runtime endpoint health：TCP/WebSocket/HTTP CONNECT/TIX-TCP 会做周期 probe，UDP/QUIC 由真实 dial/send 成功或失败更新状态；明确 down 的 endpoint 在 TTL 内不会参与候选选择，`trustixctl datapath` 会显示 `endpoint_state`。默认主动 probe 间隔为 30s、timeout 为 2s、TTL 为 90s，可用 `TRUSTIX_ENDPOINT_PROBE_INTERVAL`、`TRUSTIX_ENDPOINT_PROBE_TIMEOUT`、`TRUSTIX_ENDPOINT_HEALTH_TTL` 调整，TTL 会至少保持为 probe 间隔的 3 倍，避免空闲误过期。
- 动态 membership 学到的 route 默认不锁死第一个 endpoint，只要求成员至少有一个可拨号 endpoint，实际发送时再按策略做 endpoint 选择和 failover。
- 动态 route 会先经过本机 `route_policy.import_prefixes` 和 `route_policy.import_transit_routes` 过滤；被拒绝的 prefix、重复 prefix、冲突 prefix、禁用的 transit import 或无可拨号 endpoint 都会出现在 `trustixctl route-policy` 的决策里。`route_policy.export_prefixes` 会在本机 signed advertisement 生成时生效，未通过 export policy 的 `lan:`/`lans:` prefix 不会传播给其他 IX。静态 transit route 可覆盖同 prefix 的动态直连 route，动态导入会记录为 `duplicate_prefix`，用于强制指定路径。
- `transport_policy.mtu` 大于 0 时，Linux TC ingress 会拒绝超过该长度的 captured-path packet，并通过 `tc_packet_mtu_drops` / `MTU_EXCEEDED` 暴露；`transport_policy.fragment_policy: drop` 会在 TC 拒绝 IPv4 fragment，并通过 `tc_packet_fragment_drops` / `FRAGMENTED_PACKET` 暴露。默认 fragment policy 为空/`allow`；daemon 仍会对进入 userspace 的 packet 做同样校验。
- `kernel_udp + crypto_placement: kernel + TRUSTIX_KERNEL_UDP_TC_TX_SECURE_DIRECT=1` 会自动给 TC packet policy 下发安全 TCP MSS clamp：默认按 1500 underlay MTU 计算为 1340，或按 `transport_policy.mtu` 重新计算；`TRUSTIX_TCP_MSS_CLAMP=<n>` 可显式覆盖，`TRUSTIX_TCP_MSS_CLAMP=off` 可关闭。Linux veth/虚拟网卡压测如果仍看到 `tc_kernel_udp_tx_secure_direct_mtu_plain_max_fallbacks` 很高，通常是 GSO/TSO 大 skb 在 TC ingress 前未拆分；daemon 在 `lan.attach_mode: managed` 时默认通过 ethtool ioctl 关闭 LAN 入口的 GSO/GRO/TSO/partial-checksum 等不安全 offload，并在退出或 `-cleanup-dataplane` 时恢复。`TRUSTIX_LAN_OFFLOAD_PROTECTION=off|managed|force|required` 可覆盖策略；`existing` LAN 默认不改系统口，需要时设为 `force/required`。测试脚本的 `TRUSTIX_E2E_DISABLE_VETH_OFFLOADS=auto` 仍会额外处理测试 netns peer 侧 veth offload。
- 配置 `lan.underlay_iface` 后，TIX-TCP 和 UDP/TIXU 会在 underlay iface 上挂 embedded C eBPF XDP redirect 程序并绑定 AF_XDP socket；TrustIX TCP-shaped frame 与固定 IPv4/UDP TIXU frame 由 XDP 按目的端口 allowlist 重定向到 AF_XDP worker，带 TrustIX magic 但端口未授权的 frame 会在 XDP fail-closed drop，发送侧通过 AF_XDP TX ring 回到 underlay，不进入系统 TCP socket、UDP socket 发送队列、TCP 重传队列或拥塞控制。XDP classifier 暴露 redirect/pass/unauthorized-drop/parse-error 计数；AF_XDP 收包路径直接在 UMEM frame view 上解析 Ethernet/IPv4/TCP/TIXT 或 Ethernet/IPv4/UDP/TIXU，只为最终交付 payload 保留生命周期拷贝，并校验 IPv4/TCP/UDP checksum，错误包 fail-closed 丢弃并计入 `CHECKSUM_ERROR`。
- `transport_policy.crypto_placement` 支持 `userspace`、`auto` 和 `kernel`，并同时作用于 `tix_tcp` 与 `kernel_udp` 的 secure data AEAD offload。空配置默认是 `userspace`；显式 `auto` 会按 fallback chain 优先采用最快 ready 后端，`kernel` 会严格要求 kernel crypto provider 或 `.ko` AEAD device，`userspace` 强制 daemon AEAD。第一版只接受公共 `transport_policy.crypto_placement`。secure 握手仍在 userspace 完成身份认证和 key 派生，握手后才把 AEAD key/IV/epoch/key_source 安装给 provider；provider 可用时 data frame seal/open 由 BPF crypto kfunc、direct kfunc 或 `.ko` device 完成，否则 `auto` 退到 userspace，显式 `kernel` 报错。`trustixctl datapath` 的 `crypto_fallback.selected` 会暴露实际命中的后端。TIX-TCP 不是系统 TLS 流，`crypto_key_source: auto` 当前会使用 TrustIX X25519；真实 TCP/QUIC/WebSocket/HTTP CONNECT mTLS 链路可使用 `tls_exporter`。
- `kernel/trustix_crypto` 提供可选 out-of-tree `.ko`，用于在已有 BPF crypto kfunc 但缺少 BPF `aead` type 的发行版内核上注册 TrustIX 需要的 AEAD-GCM 能力；默认它委托 kernel crypto API，AES-NI 仍由内核 provider 决定，缺少硬件 AES 时会走内核同步 generic `gcm(aes)` / `__gcm(aes)` 软件实现。需要在有 AES-NI 的机器上强制验证软件路径时，可通过 `kernel_modules.trustix_crypto.parameters: "prefer_software=1"` 或手动 `insmod ... prefer_software=1` 加载。x86 AES/AVX2/VAES/VPCLMULQDQ 主机可加 `experimental_vaes=1` 启用 prepared mmap pool seal batch 的 TrustIX VAES/VPCLMUL 引擎；`experimental_vaes_kfunc=1` 还会让单包 kfunc crypto callback 尝试 VAES 路径，适合 TC secure-direct 这类小包内核加解密压测。默认 `vaes_agg_ghash=1` 使用 4-block aggregated GHASH，`vaes_agg_ghash=0` 可回退 GHASH loop，`vaes_fused_ghash=1` 只保留为较慢的实验对照。`vaes_attempts` 和 `vaes_fallbacks` 可用于确认是否实际命中实验路径。
- `kernel/trustix_datapath` 是完整 kernel datapath 的独立 `.ko` 落点，拥有 `/dev/trustix_datapath`、query/selftest ABI、route/session/session-wire/flow state batch ioctl 表、内核侧 route/flow/session classify 自测、dry-run IPv4 packet classify ioctl、受控 TIXT encap/decap ioctl，以及可 attach 到 IPv4 prerouting 的 hook/counters。daemon 会在该模块已加载时 best-effort 同步已接受的 IPv4 route/session/session-wire/flow records。`RX_WORKER` / `TX_PLAINTEXT` 会在内核回注或封装 plaintext skb，属于 crash-risk 实验路径；daemon 默认不会因 `performance` 配置自动启用，且会显式请求 `rx_worker_inject=0 tx_plaintext=0` 以关掉已加载模块的可写运行时开关。需要显式设置 `TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER=1` 或 `TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_FULL_PLAINTEXT=1` 才会添加 `rx_worker_inject=1` / `tx_plaintext=1` 并 attach 对应 hook；OpenWrt 还必须设置 `TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_OPENWRT_FULL_DATAPATH=1`，否则即使配置选择 `full_plaintext` 也会保持 `rx_worker_inject=0 tx_plaintext=0`。`full_plaintext` 会自动选择当前长测覆盖的基础 inline-xmit TCP stream 参数；`rx_worker_queue_skb`、RX-worker GSO coalesce、inline-pair/hold-skb、stolen skb、dev-forward、MAC-cache/hashq/xmit-more 等子实验还需要额外设置 `TRUSTIX_KERNEL_DATAPATH_ALLOW_CRASH_RISK_RX_WORKER_EXPERIMENTS=1` 才能从 raw module parameters 进入模块。secure 加密、GSO LAN TX 和更激进 direct XMIT 仍保持 gated 实验路径。
- `kernel/trustix_datapath_helpers` 是 skb/header/GSO 和 route-TCP helper kfunc 的独立 `.ko`，拥有 `/dev/trustix_datapath_helpers` 和 helper feature query ABI。当前生产能力包括 `gso_skb`、线性 route-TCP header helper，以及在 runtime capability gate 通过后供 `route_gso`、`secure_kudp` 和 `secure_tix_tcp_kernel` 使用的 route-TCP GSO/XMIT kfunc。未加载、缺 BTF/kfunc、runtime 参数不匹配，或 OpenWrt 未暴露所需 route-TCP 能力时会 fail-closed；helpers 即使误报 `full_datapath` 也不会被控制面接纳为完整 datapath。
- 可用本机 `kernel_modules.trustix_crypto`、`kernel_modules.trustix_datapath` 和 `kernel_modules.trustix_datapath_helpers` 声明让 daemon 管理三个 `.ko` 生命周期。`mode: disabled` 不触碰模块；`mode: auto` 会在模块未加载时尝试加载，失败只在 status/doctor 中告警；`mode: required` 会要求模块已加载或可由 daemon 加载，否则启动/热 apply 失败。`path` 可指向文件，也可写 `embedded` 使用 release 二进制内置的对应 `.ko`。`reload_on_upgrade: auto` 是运行时默认值：TrustIX 加载模块时注入 `build_sha256`，后续启动发现已加载模块缺少该指纹或指纹不同，且模块 `ref_count=0` 时会先卸载旧模块再加载目标 `.ko`；`never` 禁用自动升级重载，`always` 每次 ensure 都重载。daemon 使用 Linux `finit_module`/`init_module`/`delete_module` syscall，不 shell out 到 `insmod`/`rmmod`；`unload_on_exit: true` 只会在退出时卸载本进程加载的模块，不卸载外部预加载模块。
- 对端 daemon 收到 secure transport packet 后解密，并通过 AF_PACKET cooked L2 reinject 送入 LAN；运行时不再使用 raw IPv4 socket 做 LAN 回灌。若回注包是超过 LAN MTU 的普通 IPv4/TCP payload 包，会先按 LAN MTU 做软件 TCP 分段并刷新 IPv4/TCP checksum，避免 GSO 形态大包在回注侧触发 `MTU_EXCEEDED`；不能安全分段的报文仍 fail-closed。
- AF_XDP provider 支持多 RX queue 绑定、不可用队列数自动降级、按 flow/tuple 固定 TX queue、TX completion 后台回收、TX 背压短重试、neighbor cache、netlink neighbor event 同步、XDP allowed-port 热同步、session close flow 清理和 orphan flow TTL/GC，并在 `trustixctl datapath`/`trustixctl bpf maps` 暴露 RX/TX/ring/backpressure/neighbor/allowed-port/XDP classifier 统计，以及 UMEM/ring 资源占用 gauge。`TRUSTIX_AF_XDP_TX_BACKPRESSURE_WAIT` 可设置 TX frame/ring 压力下的最长短等待，默认 `2ms`，`0`/`off` 可关闭。
- `trustixctl datapath` 会输出全局 counters、active sessions、per-route 发送统计、per-peer 发送统计、per-endpoint packet/byte/error/active-session/current-flow 统计和 endpoint health state，用于定位 route、peer 或 endpoint 级故障。
- `trustixctl status` 的 `transport_tls` 会显示当前 `crypto_key_source`、`crypto_suites`、`tls_identity`、secure data `wire_format`、可提供 TLS exporter 的 endpoint 数、非 exporter endpoint 数、`link_tls: required` endpoint/session 数、TLS-only endpoint/session 数，以及 active session 中 `link_tls`/`tls_exporter` key source 的实际命中数。`trustixctl doctor` 会增加 `transport_tls` 检查：强制 `crypto_key_source: tls_exporter` 但只配置 UDP/TIX-TCP endpoint、active session 没有实际使用 TLS exporter、`link_tls: required`/TLS-only session 没有实际使用 LinkTLS，或 `custom_cert` 被用于 enabled passive listener 但缺少 transport cert/key 时会报 degraded/warn。`custom_cert` 无 cert/key 仍允许纯拨出节点使用系统/自定义 trust roots 验证对端公网/IP 证书。
- `trustixctl status` 会输出 daemon runtime resource block，包括 PID、data-dir lock 持有状态/路径、Go heap/sys、goroutine、Linux RSS 和 open FD 计数；`trustixctl doctor` 会增加 `runtime_resources` 检查，用于发现重复 daemon、异常内存、FD 或 goroutine 增长。
- `trustixctl status` 会输出 `state_files` block，覆盖 config log、`members.json` 和 `pending-members.json` 的路径、存在性、大小、mtime、权限、记录数、过期记录数和 pending 过期窗口；`trustixctl doctor` 会增加 `state_files` 检查。`trustixctl config verify` 会完整校验本地 config log 的 hash chain、seq、签名、Admin proof 和 resource 权限，并列出 `config.log.backup.<timestamp>` 备份。全量替换 config log 时默认只保留最近 16 个备份，可用 `TRUSTIX_CONFIG_LOG_BACKUP_KEEP=<N>` 调整，`0`/`off`/`disabled` 表示关闭裁剪；status/doctor 会暴露 `backup_keep`，并在历史备份超过保留数时告警。`config.log` 是授权链状态，损坏会继续阻止启动；`members.json` 和 `pending-members.json` 是可由 gossip/admission 恢复的 runtime cache，JSON 损坏时 daemon 会把坏文件隔离为 `.bad.<timestamp>` 并从空缓存继续启动。
- 配置热更新会重建 data listener/session，但不会中断 dataplane capture forwarder；`trustixctl datapath` 会通过 `capture_forwarder_active` 显示转发器状态。进程退出、API/peer server 错误或 data path 错误会显式取消 capture subscription 并关闭 data path，避免测试机上残留 goroutine/订阅。
- 动态 membership 会持久化到 `<data-dir>/members.json`，pending admission 会持久化到 `<data-dir>/pending-members.json`；两者都支持 TTL 过期清理，pending 队列当前 TTL 为 24h。稳定空闲时 peer membership 轮询默认 30s，未变化 advertisement 保活推送默认 60s；配置变化或 advertisement 内容变化仍会在下一轮同步立即传播，可用 `TRUSTIX_PEER_POLL_INTERVAL` 和 `TRUSTIX_ADVERTISEMENT_PUSH_INTERVAL` 调整。控制面 HTTP client 和管理/peer API listener 的 TCP keepalive 默认 2min，可用 `TRUSTIX_CONTROL_CLIENT_TCP_KEEPALIVE`、`TRUSTIX_SERVER_TCP_KEEPALIVE` 调整，`off` 可关闭。动态 member 支持更新为空 prefix 的路由撤销、显式删除成员 API，以及确定性的 prefix 冲突仲裁。
- IX admission 支持 domain 级 signed config log 资源 `/domain/admissions/<ix>`。`POST /v1/admissions/approve` 会写入 Admin proof 保护的批准事件，payload 绑定 `ix_id`、IX 证书 SHA256 指纹、可选 allowed prefixes、可选 route authorization 指纹、可选 control API 和 `effective_at`；`POST /v1/admissions/revoke` 会写入 revoked 状态。第一版默认要求远端 membership advertisement 匹配 approved admission，否则不会进入动态成员表；未批准广告通过基础真实性校验后可通过 `GET /v1/admissions/pending` 查看，并可用 `POST /v1/admissions/approve-pending` 从广告自动生成 IX cert fingerprint、LAN prefixes、route authorization fingerprints 和 control API；显式传入字段会覆盖广告默认值。pending API 会返回 `expires_at`、`ttl_seconds` 和 `expired`，daemon 重启、trust 变更或 admission 同步后都会重新校验 pending 广告，已经批准、过期、被吊销或基础真实性失效的记录会被清理。admission 变更或同步后会重新校验已有动态 member，prefix、route authorization、control API、IX cert 或 effective time 不再匹配的成员会被清理。批准事件同步到本地后即为本地最终授权，不做区块链式最小确认数；`GET /v1/admissions` 的 `observed_by` 只表示本地根据成员广告看到哪些 IX 的 config head 已经不低于该 admission seq，用于观测传播，不是共识确认。
- 管理 API 支持 desired config 闭环：`GET /v1/config/desired`、`POST /v1/config/validate`、`POST /v1/config/apply`、`POST /v1/config/rollback`。apply 会先验证 schema、route authorization、trust roots 和本地 IX 签名能力，再热切换 route/dataplane snapshot、本地 advertisement、data listener 和 host management API listener，成功后才追加新的 signed `/ix/<ix>/desired` config log 事件。
- 管理 API 默认仍按本地开发方式绑定 `127.0.0.1`；生产或远程运维时应启动 `-api-admin-auth`。开启后，管理 API 写请求必须带 Admin 证书签名请求头；`trustixctl` 可重复传入 `-admin-cert` / `-admin-key`，或在 `TRUSTIX_ADMIN_CERT` / `TRUSTIX_ADMIN_KEY` 中用逗号或分号分隔多组路径，自动为同一个请求附加多个 Admin proof。WebUI 也可以在浏览器内存中导入 Admin 证书和未加密 PKCS8 私钥，按同一套 `X-TrustIX-Admin-*` header 对 `/v1` 请求签名；私钥不会写入本地存储，刷新页面后需要重新导入。带 Admin 签名的配置写入会把 Admin 证书、请求 body hash、timestamp 和签名作为 `admin_proofs` 固化进 config event；peer 同步时会一起验签，因此配置链可以审计实际授权管理员。`trust.admin_policy.threshold` 大于 1 时，trust mutation 会要求达到阈值；开启 `-api-admin-auth` 后，所有管理面 mutation 也会按当前 Admin policy 验证。
- 每个管理 listener 还提供不要求 Admin proof 的 `GET/HEAD /healthz`、`/readyz` 和 `/metrics`。`healthz` 只证明 HTTP 事件循环仍能响应；`readyz` 只有在 desired config/config log 已加载、data-dir lock 已持有、dataplane stats 可读、data path 已启动且 run context 未退出时返回 200，否则返回 503 并列出失败检查；`metrics` 输出不含 domain/IX 标识的 Prometheus text 指标。`trustixctl health|ready|metrics` 可直接调用。它们仍暴露在 management listener 的网络边界上，生产环境应通过主机防火墙或采集网络限制来源。
- HTTP 边界在 Admin 验签前按 TCP `RemoteAddr` 做独立的每来源令牌桶限流，不信任 `X-Forwarded-For`：management read 默认 120 req/s、burst 240，management mutation 默认 20 req/s、burst 40，peer/control 默认 240 req/s、burst 480，`readyz/metrics` 默认 20 req/s、burst 40；`healthz` 不限流。分别用 `TRUSTIX_API_READ_RATE`/`TRUSTIX_API_READ_BURST`、`TRUSTIX_API_WRITE_RATE`/`TRUSTIX_API_WRITE_BURST`、`TRUSTIX_PEER_API_RATE`/`TRUSTIX_PEER_API_BURST`、`TRUSTIX_OPERATIONAL_API_RATE`/`TRUSTIX_OPERATIONAL_API_BURST` 调整，rate 或 burst 设为 `0`/`off`/`disabled` 会关闭对应桶。反向代理后的请求会共享代理源地址的桶，需要按汇聚并发调高，但不要用转发头改写安全边界。普通管理/peer 请求体上限为 8 MiB，配置恢复归档上限为 64 MiB；声明超限的请求在进入认证和 handler 前返回 413。429 响应带 `Retry-After: 1`，累计拒绝数可从 `trustix_http_rate_limited_total{scope=...}` 读取。
- 生产备份应使用收件公钥在内存中加密包含私钥的完整归档，源 IX 不保存解密 identity；`config verify-backup` 和 `/v1/config/validate-archive` 可做不改文件、不切 runtime 的恢复演练。密钥、systemd timer、OpenWrt cron、保留和恢复步骤见 [backup-recovery.md](backup-recovery.md)。
- 管理 API/WebUI TLS 由同一个 `management.tls` 控制，不为 WebUI 单独开监听。默认 `mode: auto`：loopback 主 API 继续用 HTTP，非 loopback 主 API、`management.host_api` 和 management VIP 自动用 HTTPS；`mode: required` 会连 loopback 也强制 HTTPS，`mode: disabled` 只建议测试使用。默认 `identity: ix_cert`，直接使用本 IX 证书；浏览器如果不信任 TrustIX CA，或访问地址不在 IX 证书 SAN 中，可以切到 `identity: custom_cert` 并配置 `cert`/`key`。`trustixctl` 访问 HTTPS 管理面时可用 `-api-tls-ca`、`-api-tls-server-name` 或临时测试用的 `-api-tls-insecure-skip-verify`。
- 当前 IX LAN 主机访问本 IX 管理面时，不需要把主 API 绑定到 `0.0.0.0`。在 desired config 中启用 `management.host_api.enabled: true` 后，daemon 会额外监听 `management.host_api.listen`；如果未配置 `listen`，会默认使用第一个配置了 gateway 的 `lan:`/`lans:` IP 和 `-api` 的端口，例如 `10.0.0.1:8787`。这个 host API 默认强制读写请求都带 Admin 签名；只有显式配置 `allow_unauthenticated_reads: true` 才允许匿名读，`allow_unauthenticated_writes: true` 会让 doctor 报 degraded。`trustixctl` 在传入 `-admin-cert/-admin-key` 后会同时给 GET 请求签名。`trustixctl status` 会输出 `management.host`，`trustixctl doctor` 会输出 `management_host_api` 安全状态。
- 内嵌 WebUI 通过 `management.web_ui.enabled: true` 启用，不启用时只保留 API。WebUI 不再有独立监听模式；API 绑定到哪里，WebUI 就跟到哪里：主 `-api` listener 可本机访问，`management.host_api` 可给当前 IX 下的 LAN 主机访问，management VIP proxy 可用于通过其他 IX 的管理 VIP 打开目标 IX 面板。默认 WebUI 资产会随二进制 embed；如果配置 `custom_dir`，daemon 会优先读取该目录下的 `index.html`、`app.css`、`app.js`、`i18n/*.json` 等同名资产，缺失项回落到嵌入版本。WebUI 响应默认带 CSP nonce、`nosniff`、`DENY` frame 和 `no-referrer` 安全头。WebUI 直接走同源 `/v1` 管理 API，因此 LAN/IX 场景下如果想让普通浏览器读取状态，需要按风险接受度配置 host API 的读认证策略；`trustixctl doctor` 会输出 `management_web_ui` 检查，标出非 loopback 主 API未签名写、host API 匿名读写和 custom UI 暴露面。
- 内置 DNS 解析器可回答 TrustIX 域内 IX 名称，例如 `ix-a.trust.ix`。未配置 `dns.upstreams` 时只回答域内名称，其他查询返回 `REFUSED`；配置上游后才转发非 TrustIX 域。OpenWrt 推荐启用 `dns.dnsmasq.enabled: true`，daemon 会监听 `127.0.0.1:1053` 并写入 dnsmasq 条件转发规则 `/domain/127.0.0.1#1053`，同时添加 `rebind_domain=domain` 白名单，允许 TrustIX 域名返回 LAN/RFC1918 地址。该模式保留 dnsmasq 继续服务 LAN 的 53 端口，不做 LAN 透明 DNS 捕获，也不改写 hosts。退出或关闭该选项时会按本机状态文件清理 TrustIX 添加的 dnsmasq 规则和 rebind 白名单。

OpenWrt dnsmasq DNS 示例：

```yaml
dns:
  enabled: true
  domain: trust.ix
  dnsmasq:
    enabled: true
```

- 当前 IX 下的主机可以通过本 IX 的 host API 跨 IX 访问其他 IX 的管理 API：`trustixctl -api https://10.0.0.1:8787 -api-tls-ca certs/domain-ca.pem -api-tls-server-name lab.local -target-ix ix-b ...` 会把请求发到本地 IX，再由本地 IX 通过 peer `control_api` mTLS 转发到目标 IX 的 `/v1/control/management`。目标 IX 会重新按自己的 trust policy 复验 Admin proof，配置写入时保留原始 proxy URI 审计，不把中转 IX 当作管理授权者。
- 远端 IX 开启 `management.host_api` 后，会在成员广告里发布管理 VIP `/32`。本地 IX 会把该 `/32` 导入为 `kind: local` / `source: management_vip`，TC/eBPF 对这个更长前缀放行，不再按远端 LAN 路由送入数据面；daemon 会在本地 LAN iface 上挂载该 VIP 并监听对应端口，把主机直连 `https://远端网关IP:端口/v1/...` 的 HTTPS 请求通过 peer `control_api` mTLS 代理到目标 IX。因此同一台主机既可以用 `-target-ix`，也可以直接把 `-api` 指向远端管理 VIP。
- Linux daemon 启动时会持有 `<data-dir>/trustixd.lock` 的进程锁；同一个 data dir 已有运行中的 `trustixd` 时，第二个 daemon 会启动失败，避免重复进程同时写 config log、members state 或 BPF state。
- daemon 退出清理会覆盖 Ctrl+C、SIGTERM、API/peer server 异常和 data path 异常路径，统一关闭 data listeners/session、停止 HTTP server、detach dataplane，按 `kernel_modules.*.unload_on_exit` 可选卸载本进程加载的 `.ko`，并释放 data-dir lock。
- 证书吊销、CA 轮换和 Admin 授权策略都通过 domain trust resource 传播，资源路径是 `/domain/trust`，v2 事件 payload 包含 `trust_epoch`、`effective_seq`、`effective_at`、SHA256 吊销列表、额外 PEM trust roots 和 Admin policy。写入 `/domain/trust` 必须带满足当前策略的 Admin proof；IX 证书只能签自己的 `/ix/<ix>/desired`，不能无授权修改 domain trust。可用 `trustix-ca verify -cert certs/admin-1.crt` 读取 `fingerprint_sha256`，配置时可写裸 64 位 hex、`sha256:<hex>` 或冒号分隔格式。热 apply 或同步收到 trust event 后会立即拒绝被吊销的 Admin 请求、peer mTLS/secure transport 证书、成员广告、route authorization 和 config signer；动态 member / data session 会按新 trust 收敛，config signer 证书缓存会保留链上历史验签材料。
- 会写入 config log 的管理面 mutation 会先对已知静态 peer、bootstrap peer 和已学习 member 做一次 config sync preflight。若本机只是落后，会先拉取缺失事件再基于最新 head 写入；若发现 hash fork/conflict，会返回 `409 Conflict`，响应包含 `local_head`、`remote_head` 和 `rejoin_hint`，管理员需要先执行 `trustixctl config rejoin <control_api> [ix_id]` 再重试。普通 peer 暂时不可达只会记录到 `config peers`/`status`，不会阻塞本地写入；这不是全局共识或 quorum，只是写前防 fork 保护。
- peer mTLS 控制面支持 config log 事件同步：`/v1/control/config/head`、`/v1/control/config/log`、`/v1/control/config/events`。空日志会先写入由 domain id 和 trust root 指纹生成的 common genesis，因此新 IX 可以通过 bootstrap 加入同一条 hash chain。同步只追加同一 hash chain 上缺失的 signed events；如果同一 seq 的 hash 不一致会标记 conflict，不会盲目合并。远端 `/ix/<ix>/desired` 事件会进入本地 config log，但不会自动覆盖本机 desired runtime 配置；远端 `/domain/admissions/<ix>` 事件同步后会立即影响本机 membership 验收并清理不再匹配的动态 member。
- peer mTLS 控制面支持完整 config snapshot 导出：`/v1/control/config/snapshot`。本地管理面支持 `POST /v1/config/rejoin` 从指定 peer 拉取完整链、验签、替换本地 config log，并默认把本机当前 runtime desired 作为本 IX 的 `/ix/<ix>/desired` 事件接到新链尾，用于安全恢复 fork/conflict 或重新加入同一 domain chain。
- config event signer certificate 会缓存在 `<data-dir>/config-signers.json`，重启后仍能校验远端 IX 签名事件。
- 将 dataplane snapshot 写入 `<data-dir>/bpf/state.json`。
- 进程正常退出时清理 TrustIX 添加的地址、qdisc，并恢复 sysctl。

真实 Linux 端到端烟测：

```bash
sudo -E bash scripts/linux-e2e-smoke.sh
```

这个脚本会在临时目录内构建 `trustixd/trustixctl/trustix-ca`，生成两套 IX 配置和证书，创建两个 LAN network namespace，通过 veth 把它们接到两个 TrustIX LAN iface，启动两个 `-dataplane linux` daemon，并验证 `10.0.0.2 <-> 10.0.1.2` 双向 ICMP 流量。验证项包括 TC route-hit、capture perf event、userspace secure transport 发送/接收、以及对端 LAN reinject 计数。脚本内搭测试拓扑会使用 `ip netns`；daemon 运行时仍由 netlink/TC/eBPF 管理，不 shell out 到 `ip`/`tc`。

常用调试开关：

```bash
TRUSTIX_E2E_KEEP=1 sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_WORKDIR=/tmp/trustix-e2e sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_BIN_DIR=/opt/trustix/bin sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TRANSPORT=tcp sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TRANSPORT=kernel_udp sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_NAT_REVERSE=1 sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_NAT_REVERSE=1 TRUSTIX_E2E_TRANSPORT=tcp sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_NAT_REVERSE=1 TRUSTIX_E2E_TRANSPORT=kernel_udp sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_NAT_REVERSE=1 TRUSTIX_E2E_TRANSPORT=tix_tcp sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TRANSPORT=gre sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TRANSPORT=ipip sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TRANSPORT=tix_tcp sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TRANSPORT=tix_tcp TRUSTIX_E2E_KERNEL_MODULE=1 sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TRANSPORT=tix_tcp TRUSTIX_E2E_KERNEL_MODULE=1 TRUSTIX_E2E_CRYPTO_PLACEMENT=kernel sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_E2E_TCP_PROBE=1 sudo -E bash scripts/linux-e2e-smoke.sh
TRUSTIX_SECURITY_SMOKE_ROOT=1 sudo -E bash scripts/linux-security-smoke.sh
TRUSTIX_SECURITY_SMOKE_ROOT=1 TRUSTIX_SECURITY_SMOKE_HEAVY=1 sudo -E bash scripts/linux-security-smoke.sh
TRUSTIX_TIX_TCP_BENCH_BIN_DIR=/opt/trustix/bin sudo -E bash scripts/linux-tix-tcp-bench.sh
TRUSTIX_KERNEL_TEST_BIN=/opt/trustix/bin/ebpf.test sudo -E bash scripts/linux-kernel-module-smoke.sh
TRUSTIX_DATAPATH_KERNELMODULE_TEST_BIN=/opt/trustix/bin/kernelmodule.test sudo -E bash scripts/linux-datapath-module-smoke.sh
TRUSTIX_IPTUNNEL_SMOKE_PROTOCOL=gre sudo -E bash scripts/linux-iptunnel-smoke.sh
TRUSTIX_IPTUNNEL_SMOKE_PROTOCOL=ipip sudo -E bash scripts/linux-iptunnel-smoke.sh
TRUSTIX_3IX_E2E_BIN_DIR=/opt/trustix/bin sudo -E bash scripts/linux-three-ix-e2e-smoke.sh
TRUSTIX_3IX_E2E_BIN_DIR=/opt/trustix/bin TRUSTIX_3IX_E2E_KERNEL_MODULE=1 TRUSTIX_3IX_E2E_CRYPTO_PLACEMENT=kernel sudo -E bash scripts/linux-three-ix-e2e-smoke.sh
```

`TRUSTIX_E2E_KEEP=1` 会保留 netns、veth、daemon 日志和 `trustixctl` 采集结果，便于继续查看 `capture`、`datapath`、`transports`、`bpf maps` 和 daemon log。`TRUSTIX_E2E_BIN_DIR` 可以指向已有的 `trustixd/trustixctl/trustix-ca` Linux 二进制目录，从而在没有 Go toolchain 的测试机上跳过构建。脚本会自动避开本机已占用的默认 API、peer API、UDP、TCP 和 tix_tcp 端口；需要固定端口时仍可显式设置 `TRUSTIX_E2E_*_PORT`。默认烟测使用 UDP secure transport 来验证 TC/eBPF capture/reinject 主链路、data-dir lock 状态、重复 data-dir 启动拒绝，以及 SIGTERM 后释放 data-dir lock 并原地重启；`TRUSTIX_E2E_NAT_REVERSE=1` 会启用 IX router netns，用 ix-b 模拟无公网/NAT 节点：ix-b 本地 endpoint 只 listen 不发布 address，ix-a 对 ix-b 的 peer endpoint 是 `mode: passive` 且无 address，脚本先跑 B->A 预热 outbound secure session，再验证 A->B 复用 `reverse://inbound` 反向 session，并断言 `datapath.sessions[].reverse`、`direction=inbound_reverse`、`transports.peer_endpoints[].reverse_only` 和 `active_reverse_sessions`。NAT reverse smoke 覆盖 `udp`、`tcp`、`kernel_udp` 和 `tix_tcp`；其中 `tcp` 会继续使用 transport TLS exporter + custom_cert，`kernel_udp` 和 `tix_tcp` 会验证 no-public 本地 listen 仍进入 XDP/AF_XDP allowed-port fast path。`TRUSTIX_E2E_CRASH_RESTART=0` 可跳过 crash/restart 段。`TRUSTIX_E2E_TRANSPORT=tcp` 会生成独立 transport TLS IP SAN 证书，使用 `transport_policy.crypto_key_source: tls_exporter` 和 `tls_identity.mode: custom_cert` 跑同一套双向 LAN 流量，并断言 `status.transport_tls`、`datapath.sessions[].stats.link_tls`、TLS 1.3/cipher suite 和 `transport_tls` doctor 都正确。`TRUSTIX_E2E_TRANSPORT=kernel_udp` 会自动启用两个 IX router netns 和独立 underlay veth，在 UDP endpoint 上写入 `transport_policy.kernel_transport.mode: require_kernel`，验证 UDP/TIXU 的 `kernel_udp` 状态、`kernel_transport.protocols[].udp`、offload placement、doctor、XDP/AF_XDP 模式协商、allowed-port map、active flow、submitted/received frame、TIXU 大包分片/重组统计和 AF_XDP backpressure/error/`mtu_exceeded` 计数。`TRUSTIX_E2E_TRANSPORT=gre` / `ipip` 会同样启用两个 IX router netns 和 underlay veth，在每个 IX 本地创建方向正确的 GRE/IPIP netdev，并在 tunnel 内用 UDP carrier 跑完整 secure data path；脚本会断言 `kernel_transport.protocols[].gre/ipip` capability ready、`userspace_fallback=false`、session `iptunnel_mtu`/drop/error 统计、`<data-dir>/iptunnel/state.json` cleanup plan 和 crash cleanup 后无残留 tunnel link。`TRUSTIX_E2E_IPTUNNEL_PORT` 和 `TRUSTIX_E2E_IPTUNNEL_MTU` 可覆盖 tunnel 内 carrier UDP 端口和 fail-closed MTU。`TRUSTIX_E2E_TRANSPORT=tix_tcp` 会自动启用两个 IX router netns 和独立 underlay veth，验证 `provider=af_xdp`、fast path/reinject、raw fallback 关闭、XDP/AF_XDP 模式协商状态、XDP allowed-port map、XDP redirect counter、AF_XDP RX/TX/UMEM direct-build 计数、datapath route/endpoint stats、双向 LAN 转发，并额外断言 `kernel` crypto placement 在 provider 未实现时严格拒绝而不是降级；如果测试机已预加载 `trustix_crypto`，这项“provider 不可用”预检会跳过。tix_tcp 烟测还会注入未授权端口 TrustIX magic 包和授权端口坏 TCP checksum 包，断言 XDP unauthorized drop、AF_XDP checksum error 和 `CHECKSUM_ERROR` drop reason。测试 veth 默认使用 `TRUSTIX_E2E_AF_XDP_QUEUES=1`，需要多队列压测时可显式调大；`TRUSTIX_E2E_XDP_MODE` 和 `TRUSTIX_E2E_AF_XDP_BIND_MODE` 可强制 native/SKB 与 zero-copy/copy 模式；`TRUSTIX_E2E_AF_XDP_TX_BACKPRESSURE_WAIT` 可覆盖 TX 背压短等待；`TRUSTIX_E2E_PING_COUNT`、`TRUSTIX_E2E_PING_SIZE`、`TRUSTIX_E2E_PING_PARALLEL` 和 `TRUSTIX_E2E_PING_ROUNDS` 可提高双向 LAN ping 压力。需要 payload burst 压测时可设置 `TRUSTIX_E2E_UDP_BURST_PACKETS` / `TRUSTIX_E2E_UDP_BURST_SIZE` / `TRUSTIX_E2E_UDP_BURST_PARALLEL` / `TRUSTIX_E2E_UDP_BURST_ROUNDS`，以及 `TRUSTIX_E2E_TCP_BURST_CONNECTIONS` / `TRUSTIX_E2E_TCP_BURST_SIZE` / `TRUSTIX_E2E_TCP_BURST_PARALLEL` / `TRUSTIX_E2E_TCP_BURST_ROUNDS`；脚本会在两方向各启动 Python socket receiver/sender，验证全部 payload 到达，再继续断言 AF_XDP TX/RX/ring/backpressure 错误计数为 0。

`scripts/linux-three-ix-e2e-smoke.sh` 会搭建 ix-a/ix-b/ix-c 三个 IX router netns 和三个 LAN netns，默认使用 `tix_tcp` AF_XDP fast path。`TRUSTIX_3IX_E2E_TRANSPORT` 可覆盖为 `udp`、`kernel_udp`、`tcp`、`quic`、`websocket`、`http_connect`、`tix_tcp`、`gre`、`ipip` 或 `vxlan`；GRE/IPIP/VXLAN 会为 A-B、B-C、A-C 生成各自的点对点 tunnel endpoint。它验证 bootstrap gossip、ix-c export policy 拒绝/放行、ix-a import policy 拒绝/放行、dynamic metric、A/B、B/C、A/C LAN 流量、UDP/TCP payload burst、userspace/kernel crypto placement、data-dir lock 清理，以及热 apply 后 `owner: ix-c` + `next_hop: ix-b` 的显式 transit route；脚本会用 ix-b 的 datapath peer counter 断言 A 到 C 的包确实经过 ix-b 转发。

`scripts/linux-tix-tcp-bench.sh` 会复用二 IX e2e，默认跑 `tix_tcp` userspace crypto placement，并打开 ping、UDP burst 和 TCP burst，最后输出每个 IX 的 JSON 汇总：总耗时、effective crypto、AF_XDP/XDP 模式、TX UMEM direct-build、kernel crypto TX seal/RX open、ring/backpressure 和错误计数。bench 默认把二 IX e2e 的 crash/restart 段关掉，避免压测失败或远端 SSH 中断时扩大清理面；需要覆盖 crash repair 时可设 `TRUSTIX_TIX_TCP_BENCH_E2E_CRASH_RESTART=1`。`TRUSTIX_TIX_TCP_BENCH_KERNEL=auto` 是默认值：检测到 `trustix_crypto` 已加载或设置 `TRUSTIX_TIX_TCP_BENCH_KERNEL_MODULE=1` 时，会额外跑 kernel placement；可用 `TRUSTIX_TIX_TCP_BENCH_KERNEL=0` 只跑 userspace。压测脚本会透传 `TRUSTIX_TIX_TCP_BENCH_TCP_CONNECT_TIMEOUT`、`TRUSTIX_TIX_TCP_BENCH_SESSION_POOL_*`、`TRUSTIX_TIX_TCP_BENCH_CAPTURE_FORWARDER_*`、`TRUSTIX_TIX_TCP_BENCH_AF_XDP_QUEUES`、`TRUSTIX_TIX_TCP_BENCH_AF_XDP_TX_BACKPRESSURE_WAIT` 和 `TRUSTIX_TIX_TCP_BENCH_AF_XDP_TX_KICK_BATCH`，用于定位连接建立、capture forwarder 并发和 AF_XDP TX 背压。

`scripts/linux-kernel-module-smoke.sh` 会在目标内核上构建并加载 `kernel/trustix_crypto`，再运行 kernel AEAD-GCM synthetic context lifecycle/roundtrip、frame seal/open/replay、send sequence reuse 拒绝和 TX XDP packet seal 测试；默认保留模块加载状态，`TRUSTIX_KERNEL_KEEP_LOADED=0` 时只会卸载本次脚本加载的模块。脚本会额外断言第一版 hard-disabled 的 `kfunc_simd_fastpath` 不能被打开。设置 `TRUSTIX_KERNEL_EXPERIMENTAL_VAES=1` 会以 `experimental_vaes=1` 加载模块；再提供 `TRUSTIX_KERNEL_KERNELMODULE_TEST_BIN=/path/to/kernelmodule.test` 时，脚本会跑 prepared-batch ioctl 正确性，断言 `vaes_attempts` 增加且 `vaes_fallbacks` 不增加；`TRUSTIX_KERNEL_EXPECT_VAES=1` 会要求目标主机必须报告 `vaes_available=Y` 和默认 `vaes_agg_ghash=Y`。`TRUSTIX_KERNEL_VAES_BENCH=1` 会额外输出 prepared-pool microbench。部分 cloud 内核虽然可以加载 `.ko` 并通过 `/dev/trustix_crypto` ioctl 使用 module/device batch AEAD，但 BPF verifier 不接受 crypto kfunc selftest；`TRUSTIX_KERNEL_ALLOW_UNSUPPORTED_KERNEL=1` 会把这种情况返回为退出码 2，供 release 脚本记录能力跳过，而不是误判包损坏。`TRUSTIX_E2E_KERNEL_MODULE=1` 会让 tix_tcp e2e 在 daemon 启动前先调用该烟测，并额外断言 daemon 的 `kernel_crypto_ctx_provider_loaded`、AEAD-GCM ctx create/roundtrip success 计数为正且错误计数为 0。再加 `TRUSTIX_E2E_CRYPTO_PLACEMENT=kernel` 时，e2e 会要求 `kernel_crypto=true`、`provider_ready=true`、`effective_crypto=kernel`，并断言真实双向 LAN 流量产生 `kernel_crypto_frame_seal_successes`、`kernel_crypto_frame_open_successes`、`kernel_crypto_rx_attached`、`kernel_crypto_tx_packet`、TX packet seal success 和 XDP attached open success，且 TX/XDP kernel_crypto error/replay/no-context/header error 计数为 0；若启动期出现 recv ctx 安装竞态，会记录 `xdp_kernel_crypto_deferred_to_userspace` 而不是 `xdp_kernel_crypto_no_context_drops`。生产 fast path 默认不再对每个 TX seal 输出做 userspace 解析校验，需要定位内核封包问题时可设置 `TRUSTIX_TIX_TCP_VALIDATE_TX_SEAL=1` 打开这层调试校验。

`scripts/linux-full-datapath-module-smoke.sh` 会在目标内核上构建并加载 `kernel/trustix_datapath`，验证 `/dev/trustix_datapath`、sysfs `selftests=1023` / `selftest_failures=0`、route/session/session-wire/flow state ABI、packet classify、TIXT encap/decap、基于 session-wire 的受控外层 IPv4 UDP/TIX-TCP 构包/解析 ioctl、veth ingress 下的 RX_STAGE staging ring peek/pop、RX_WORKER 注入和 TX_PLAINTEXT plaintext LAN 封装。请求 `full_datapath` 时脚本会自动补 `rx_worker_inject=1 tx_plaintext=1`，期望 `features=128` / `safe_features=128` / `unsafe_features=0`，并断言 stolen/direct XMIT、RX stream/coalesce、checksum trust、MAC cache 等第一版 panic-risk 参数都被强制关闭。daemon 在模块已加载且配置了 underlay interface 时可用 `RX_PREVIEW|RX_STAGE` 继续走 hybrid staging，也可在 `TRUSTIX_KERNEL_DATAPATH_FULL_PLAINTEXT=1` 时同时 attach underlay RX worker hook 和 LAN TX plaintext hook，让 plaintext 数据面两方向都在 `.ko` 内完成。

2026-06-10 PVE A/B 多传输长测把硬锁/重启触发点收窄到 full datapath 的 RX_STAGE hook 自动挂载，不是 `trustix_datapath` 模块加载本身。daemon 默认不再自动 attach RX_STAGE/RX_WORKER hook；需要显式配置 `kernel_modules.datapath.rx_stage: stage|worker`，或设置 `TRUSTIX_KERNEL_DATAPATH_RX_STAGE=1|worker` / `TRUSTIX_KERNEL_DATAPATH_RX_WORKER=1`。RX_WORKER 和 full plaintext 仍需要对应 crash-risk gate；被 gate 拒绝时不会回退到 RX_STAGE poller。

`scripts/linux-datapath-module-smoke.sh` 会在目标内核上构建并加载 `kernel/trustix_datapath_helpers`，验证 `/dev/trustix_datapath_helpers`、sysfs `selftests=3` / `selftest_failures=0`、TIXT selftest OK flag、`gso_skb` safe feature，以及 Go ioctl query/selftest ABI。基础 helper smoke 默认断言 route-TCP XMIT worker 和 async 路径保持关闭；生产 `route_gso`、`secure_kudp` 和 `secure_tix_tcp_kernel` 的 route-TCP GSO/XMIT 参数由 cross-host runner 显式启用并由生产 verifier 校验。outer-GSO batch 和 TIXT RX stream/coalesce 仍由模块 init 与 daemon 参数过滤共同 hard-disable。设置 `TRUSTIX_DATAPATH_ENABLE_FEATURES=0` 可验证 feature gate 禁用路径。

`scripts/linux-iptunnel-smoke.sh` 会创建两个 network namespace 和一对 underlay veth，然后运行 `cmd/trustix-iptunnel-smoke` 通过 Go transport 在 namespace 内用 netlink 创建 GRE/IPIP tunnel netdev，隧道内使用固定 UDP carrier 收发一个 TrustIX packet 并断言统计和 tunnel link 清理。脚本使用 `ip netns` 只负责测试拓扑；GRE/IPIP tunnel 创建、地址配置、link up 和删除由 `internal/transport/iptunnel` 完成，不走 raw socket fallback。endpoint 格式为 `local=<underlay-ip>,remote=<underlay-ip>,local_carrier=<carrier-ip/prefix>,remote_carrier=<carrier-ip>[,port=<udp-port>,mtu=<bytes>]`。完整数据面烟测用 `TRUSTIX_E2E_TRANSPORT=gre|ipip`；最小 smoke 只验证 carrier。

自定义传输 TLS 证书示例：

```bash
trustix-ca ix issue -domain lab.local -ix ix-a -out certs -ip 203.0.113.10 -dns ix-a.example.com
```

```yaml
transport_policy:
  # secure | plaintext | send_encrypted | receive_encrypted
  # 只控制 data packet envelope；TrustIX hello/IX 身份认证仍会执行。
  encryption: secure
  crypto_key_source: tls_exporter
  tls_identity:
    mode: custom_cert
    cert: ./certs/ix-a-transport.crt
    key: ./certs/ix-a-transport.key
    system_roots: true
    trust_roots:
      - ./certs/private-transport-root.pem

peers:
  - id: ix-b
    domain: lab.local
    tls_server_name: 203.0.113.20
    endpoints:
      - name: b-tcp
        address: 203.0.113.20:7000
        transport: tcp
        security:
          # 可按 endpoint 覆盖全局 data envelope 策略；拨出端会使用互补方向。
          encryption: secure
        # endpoint 级配置会覆盖 peer.tls_server_name。
        # tls_server_name: ix-b.example.com
```

`custom_cert` 只影响底层 TLS 证书链和 TLS exporter；TrustIX secure overlay 仍校验 peer 的 IX 证书 role/domain/ix 和吊销状态。
如果本机只主动拨出、不监听 TCP/WebSocket/HTTP CONNECT/QUIC 传输 endpoint，`custom_cert` 的 `cert`/`key` 可以省略；一旦有 passive listener，就必须配置本机传输证书和私钥。客户端校验对端公网/IP 证书时可用 `system_roots: true`，私有 CA 则放进 `trust_roots`。

构建可分发 release 包：

```bash
sudo -E bash scripts/build-release-linux.sh
```

这个脚本必须在 Linux 目标内核或具备目标 `KDIR` 的构建机上运行，因为 `trustix_crypto.ko`、`trustix_datapath.ko` 和 `trustix_datapath_helpers.ko` 都与内核版本绑定。默认行为：

- 用 `clang -target bpfel` 重新编译 `kernel/bpf/dataplane/*.c` 为 eBPF `.o`，并通过 Go build overlay 嵌入 `trustixd`。
- 用 `make -C kernel/trustix_crypto KDIR=/lib/modules/$(uname -r)/build`、`make -C kernel/trustix_datapath ...` 和 `make -C kernel/trustix_datapath_helpers ...` 构建三个 `.ko`。
- 通过 Go build overlay 把三个 `.ko` 嵌入 `trustixd`，同时在 release 包里保留 `kernel/trustix_crypto.ko`、`kernel/trustix_datapath.ko` 和 `kernel/trustix_datapath_helpers.ko`。
- 编译 `trustixd`、`trustixctl`、`trustix-ca`，以及可选的 `ebpf.test`/`kernelmodule.test`。
- 通过 ldflags 写入 `version`/`commit`/`built_at`，并生成 `manifest.json`；daemon `/v1/status` 会输出 build block、embedded eBPF `.o` hash 和 `embedded_kos` hash/ELF 状态。
- 输出 `build/release/trustix-linux-<GOARCH>.tar.gz`，例如 `trustix-linux-amd64.tar.gz` 或 `trustix-linux-arm64.tar.gz`。

常用覆盖项：

```bash
GOARCH=arm64 KDIR=/path/to/arm64/kernel/build sudo -E bash scripts/build-release-linux.sh
GOARCH=arm64 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- KDIR=/path/to/arm64/kernel/build sudo -E bash scripts/build-release-linux.sh
KDIR=/lib/modules/$(uname -r)/build sudo -E bash scripts/build-release-linux.sh
TRUSTIX_RELEASE_VERSION=v0.1.0 TRUSTIX_RELEASE_COMMIT=$(git rev-parse --short=12 HEAD) sudo -E bash scripts/build-release-linux.sh
TRUSTIX_RELEASE_GO=/usr/local/go/bin/go sudo -E bash scripts/build-release-linux.sh
TRUSTIX_RELEASE_BUILD_KO=0 bash scripts/build-release-linux.sh
TRUSTIX_RELEASE_EMBED_KO=0 sudo -E bash scripts/build-release-linux.sh
TRUSTIX_RELEASE_BUILD_TESTS=0 sudo -E bash scripts/build-release-linux.sh
```

如果只需要为一个或多个内核构建 `.ko`，不生成完整 release 包，可以使用模块构建入口：

```bash
sudo -E bash scripts/build-kernel-modules-linux.sh
ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- TRUSTIX_KERNEL_MODULE_KDIRS=/path/to/kernel-6.6/build,/path/to/kernel-6.1/build bash scripts/build-kernel-modules-linux.sh
TRUSTIX_CRYPTO_BUILD_MODE=auto TRUSTIX_DATAPATH_HELPERS_BUILD_MODE=auto bash scripts/build-kernel-modules-linux.sh /path/to/openwrt/kernel/build
```

输出位于 `build/kernel-modules/<kernelrelease>/<ARCH>/...`，并生成 `build/kernel-modules/manifest.json`。`TRUSTIX_DATAPATH_HELPERS_BUILD_MODE=auto` 会先构建 full/kfunc helpers，失败时降级到 `basic`；`TRUSTIX_CRYPTO_BUILD_MODE=auto` 会先构建 full crypto，失败时降级到 `device-only`，适合缺 BTF/kfunc 的 OpenWrt 或软路由内核。降级模块保留设备 ioctl/控制面 fallback 能力，但不会提供 TIX-TCP route-GSO/kfunc fast path。

release 包构建后可在目标 Linux 主机上跑包级烟测：

```bash
arch=$(go env GOARCH)
sudo -E TRUSTIX_RELEASE_TARBALL=build/release/trustix-linux-${arch}.tar.gz bash scripts/release-smoke-linux.sh
```

该烟测会解包、生成临时证书、自动避开本机已占用的默认 API/peer API 端口，用 `-dataplane noop` 启动单 IX daemon、读取 `status`/`doctor`，并断言 build metadata、embedded eBPF `.o`、`embedded_kos` metadata 和 `transport_tls` 诊断完整；root 且默认 `TRUSTIX_RELEASE_SMOKE_REQUIRE_MODULES=1` 时会用 `mode: required` 验证 embedded `trustix_crypto.ko` 能在当前内核加载，并用 `mode: auto` 探测 embedded `trustix_datapath.ko` 与 `trustix_datapath_helpers.ko`，随后分别运行 full datapath ABI skeleton 和 helper module smoke，默认 `TRUSTIX_RELEASE_SMOKE_UNLOAD_MODULES_ON_EXIT=1` 会断言该 daemon 自己加载的模块在退出后被卸载。`TRUSTIX_RELEASE_SMOKE_TLS` 和 `TRUSTIX_RELEASE_SMOKE_NAT_REVERSE` 默认都是 `auto`，root 执行时会继续调用 release 包内 `scripts/linux-e2e-smoke.sh` 跑 TCP TLS exporter + `custom_cert` 双 IX真实数据面烟测，以及 UDP/TCP/kernel_udp/tix_tcp NAT/no-public reverse session 烟测；可分别设为 `0` 跳过或设为 `1` 强制执行。`TRUSTIX_RELEASE_SMOKE_CONTROL=1` 会串上 membership 和 trust-policy 控制面 smoke，`TRUSTIX_RELEASE_SMOKE_3IX=1` 会串上三 IX tix_tcp 数据面 smoke，`TRUSTIX_RELEASE_SMOKE_3IX_KERNEL_UDP=1` 会串上三 IX kernel_udp 数据面 smoke，`TRUSTIX_RELEASE_SMOKE_TIX_TCP_BENCH=1` 会串上 tix_tcp benchmark/smoke 汇总。

如果要在干净测试机上验证“从源码构建 release -> release 包内 embedded `.ko` 自动加载/卸载 -> 外置 packaged `trustix_crypto.ko` 能跑 TrustIX kernel module smoke -> release 包内脚本跑 kernel transport e2e -> 测完无模块/netns/tmp 残留”，可以直接跑：

```bash
sudo -E bash scripts/linux-clean-release-smoke.sh
```

`TRUSTIX_CLEAN_RELEASE_SMOKE_TLS`、`TRUSTIX_CLEAN_RELEASE_SMOKE_NAT_REVERSE`、`TRUSTIX_CLEAN_RELEASE_SMOKE_KERNEL`、`TRUSTIX_CLEAN_RELEASE_SMOKE_KERNEL_UDP`、`TRUSTIX_CLEAN_RELEASE_SMOKE_3IX_KERNEL_UDP`、`TRUSTIX_CLEAN_RELEASE_SMOKE_TIX_TCP_KERNEL` 可分别关闭对应阶段；默认都会执行。该脚本会清理 TrustIX 命名的临时目录、`tix-*` netns 和 `/lib/modules/$(uname -r)/extra/trustix_crypto.ko`、`trustix_datapath.ko`、`trustix_datapath_helpers.ko` 残留，所以只建议在专用测试机上运行。

普通用户控制面烟测也会验证 data-dir lock 和 SIGTERM 清理：

```bash
arch=$(go env GOARCH)
TRUSTIX_MEMBERSHIP_SMOKE_BIN_DIR=build/linux-${arch} bash scripts/linux-membership-smoke.sh
TRUSTIX_POLICY_SMOKE_BIN_DIR=build/linux-${arch} bash scripts/linux-trust-policy-smoke.sh
```

控制面 trust policy 烟测：

```bash
TRUSTIX_POLICY_SMOKE_BIN_DIR=/opt/trustix/bin bash scripts/linux-trust-policy-smoke.sh
```

这个脚本不需要 root，会启动两个 noop dataplane daemon，验证 `trust apply-policy`、多 Admin threshold 拒绝/接受、`trust roots add`、新 CA 签发 Admin 继续授权 trust mutation、写前 config sync preflight，以及 `config rejoin` 后 trust roots / Admin policy 传播。

三 IX 动态 membership / route policy 烟测：

```bash
TRUSTIX_MEMBERSHIP_SMOKE_BIN_DIR=/opt/trustix/bin bash scripts/linux-membership-smoke.sh
```

这个脚本不需要 root，会启动 ix-a、ix-b、ix-c 三个 noop dataplane daemon：ix-a 只 bootstrap 到 ix-b，ix-b/ix-c 互相 bootstrap。脚本会验证 ix-a 通过 ix-b 学到 ix-c 成员，验证 ix-c `export_prefixes` 拒绝时不传播路由，热 apply 放开 export 后 ix-b 学到 ix-c 路由，随后验证 ix-a `import_prefixes` 拒绝/放行 ix-c 路由和 `dynamic_metric` 生效。

查询：

```powershell
go run ./cmd/trustixctl status
go run ./cmd/trustixctl routes
go run ./cmd/trustixctl route-policy
go run ./cmd/trustixctl peers
go run ./cmd/trustixctl members
go run ./cmd/trustixctl endpoints
go run ./cmd/trustixctl config desired
go run ./cmd/trustixctl config peers
go run ./cmd/trustixctl config head
go run ./cmd/trustixctl config log
go run ./cmd/trustixctl config log 1 3
go run ./cmd/trustixctl config event 2
go run ./cmd/trustixctl config verify
go run ./cmd/trustixctl config snapshot
go run ./cmd/trustixctl config validate configs/lab-a.yaml
go run ./cmd/trustixctl config apply configs/lab-a.yaml
go run ./cmd/trustixctl config rollback
go run ./cmd/trustixctl config rejoin https://127.0.0.1:9444 ix-b
go run ./cmd/trustixctl config restore-backup .trustix/config.log.backup.20260430T120000Z
go run ./cmd/trustixctl members delete ix-c
go run ./cmd/trustixctl trust show
go run ./cmd/trustixctl trust policy
go run ./cmd/trustixctl trust admins
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key trust apply-policy policy.json
go run ./cmd/trustixctl trust roots
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key trust roots add certs/new-root-ca.pem
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key trust roots remove certs/old-root-ca.pem
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key trust revoke certs/ix-c.crt
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key trust unrevoke <fingerprint_sha256>
go run ./cmd/trustixctl capture
go run ./cmd/trustixctl capture -limit 100 -hook lan_ingress_route_hit -peer ix-b -src 10.0.0.2 -dst 10.0.1.2
go run ./cmd/trustixctl datapath
go run ./cmd/trustixctl doctor
```

查看证书指纹并加入 domain trust 吊销列表：

```powershell
go run ./cmd/trustix-ca verify -cert certs/admin-1.crt
```

```yaml
trust:
  revoked_cert_fingerprints:
    - sha256:<fingerprint_sha256>
  trust_roots_pem:
    - |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
  admin_policy:
    threshold: 2
    allowed_fingerprints:
      - sha256:<admin-1-fingerprint>
      - sha256:<admin-2-fingerprint>
```

上面的 YAML 字段仍可作为本地初始 trust state；生产运维建议用 `trustixctl trust revoke`、`trustixctl trust roots add/remove` 或 `trustixctl trust apply-policy` 写入 `/domain/trust`，这样其他 IX 会通过 config log 同步收到同一 trust epoch。`admin_policy.threshold: 0` 等价于默认阈值 1，不表示关闭授权。

本机 `.ko` 生命周期配置示例：

```yaml
kernel_modules:
  trustix_crypto:
    mode: required
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: false
  trustix_datapath_helpers:
    mode: auto
    path: embedded
    reload_on_upgrade: auto
    unload_on_exit: false

transport_policy:
  crypto_placement: kernel
```

这个配置只作用于当前 IX 的本机 daemon。它可以随 `/ix/<ix>/desired` 进入配置链用于审计和恢复，但不会让其他 IX 自动在自己的机器上执行模块加载；其他节点需要各自声明自己的 node-level capability。

Admin policy JSON 示例：

```json
{
  "threshold": 2,
  "allowed_fingerprints": [
    "sha256:<admin-1-fingerprint>",
    "sha256:<admin-2-fingerprint>"
  ]
}
```

阈值策略生效后，后续 trust 修改需要多组 Admin 签名：

```powershell
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key -admin-cert certs/admin-2.crt -admin-key certs/admin-2.key trust revoke certs/ix-c.crt
```

开启管理 API 写认证：

```powershell
go run ./cmd/trustixd -api 0.0.0.0:8787 -api-admin-auth
go run ./cmd/trustixctl -api https://127.0.0.1:8787 -api-tls-ca certs/domain-ca.pem -api-tls-server-name lab.local -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key config apply configs/lab-a.yaml
```

给当前 IX 下的 LAN 主机开放本 IX 管理入口时，优先使用 desired config 的 host API，而不是把主 API 直接暴露到所有网卡：

```yaml
management:
  tls:
    mode: auto
    identity: ix_cert
  host_api:
    enabled: true
    # 省略 listen 时默认使用第一个配置了 gateway 的 lan:/lans: IP 和 -api 的端口，例如 10.0.0.1:8787。
    listen: 10.0.0.1:8787
  web_ui:
    enabled: true
    # custom_dir: ./webui
```

```powershell
go run ./cmd/trustixctl -api https://10.0.0.1:8787 -api-tls-ca certs/domain-ca.pem -api-tls-server-name lab.local -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key status
go run ./cmd/trustixctl -api https://10.0.0.1:8787 -api-tls-ca certs/domain-ca.pem -api-tls-server-name lab.local -target-ix ix-b -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key status
go run ./cmd/trustixctl -api https://10.0.1.1:8788 -api-tls-ca certs/domain-ca.pem -api-tls-server-name lab.local -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key status
```

运行第二个实验节点时需要使用不同 API 端口和数据目录：

```powershell
go run ./cmd/trustixd -config configs/lab-b.yaml -data-dir .trustix-b -api 127.0.0.1:8788 -peer-api 127.0.0.1:9444
go run ./cmd/trustixctl -api http://127.0.0.1:8788 status
```

同时运行 `configs/lab-a.yaml` 和 `configs/lab-b.yaml` 后，两个节点会通过 `control_api` 互相拉取广告：

```powershell
go run ./cmd/trustixctl peers
go run ./cmd/trustixctl doctor
```

动态加入的最小配置形状如下。`ix.control_api` 是对外传播给其他 IX 的控制面地址；passive endpoint 建议同时写 `listen` 和可被远端访问的 `address`。动态前缀广告需要 route authorization 证书，并且接收方的 `domain.trust_roots` 需要包含签发该证书的 CA。

如果 domain 已经启用链上 admission，需要先用 Admin 证书批准该 IX。批准可以绑定 IX 证书指纹、允许传播的前缀、route authorization 证书指纹和 control API；没有写入可选字段时只按 IX 证书指纹做准入：

```powershell
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key admissions approve `
  -ix ix-c `
  -ix-cert certs/ix-c.crt `
  -prefix 10.0.2.0/24 `
  -route-auth certs/ix-c-route.crt `
  -control-api https://c.example.com:9443

go run ./cmd/trustixctl admissions
go run ./cmd/trustixctl admissions show ix-c
```

也可以先让新 IX 只连接 bootstrap。接收方会把通过基础校验但缺少 admission 的广告放入 pending 队列，管理员确认后从广告默认值生成 admission：

```powershell
go run ./cmd/trustixctl admissions pending
go run ./cmd/trustixctl admissions pending ix-c
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key admissions approve-pending ix-c
```

pending 队列会写入 `<data-dir>/pending-members.json`，重启后仍可继续审批；每条记录按最近一次观测时间计算 24h TTL，`admissions pending` 会显示过期时间和剩余秒数。

批准进入本地 config log 后会通过 peer config sync 传播。已经同步该事件的 IX 会接受匹配的 signed advertisement；尚未同步的 IX 会继续把广告保留在 pending，直到同步完成。撤销时写入 revoked admission：

```powershell
go run ./cmd/trustixctl -admin-cert certs/admin-1.crt -admin-key certs/admin-1.key admissions revoke ix-c
```

```yaml
ix:
  id: ix-c
  cert: ./certs/ix-c.crt
  key: ./certs/ix-c.key
  control_api: https://c.example.com:9443
  route_authorizations:
    - ./certs/ix-c-route.crt

lan:
  iface: br-lan-c
  underlay_iface: eth0
  gateway: 10.0.2.1/24
  advertise:
    - 10.0.2.0/24

endpoints:
  - name: c-udp
    mode: passive
    listen: 0.0.0.0:7003
    address: c.example.com:7003
    transport: udp
    enabled: true

bootstrap:
  peers:
    - control_api: https://a.example.com:9443

routes: []

route_policy:
  import_prefixes:
    - 10.0.0.0/8
  export_prefixes:
    - 10.0.2.0/24
  dynamic_metric: 1000
  import_transit_routes: true
  transit_forwarding: true

transport_policy:
  mtu: 1500
  fragment_policy: drop
```

`route_policy.import_transit_routes` 控制是否安装通过另一个 IX 间接学到的动态路由；默认开启。`route_policy.transit_forwarding` 控制本 IX 是否把“从其它 IX 收到、目的地又不属于本地 LAN”的包继续转发给下一跳 IX；默认开启。边缘 IX 可以把两者设为 `false`，此时本地 LAN 主动访问域内其它前缀仍可按本机路由出站，但不会承载二跳中转流量。

显式 transit route 示例：下面的配置表示 `10.0.2.0/24` 的前缀拥有者是 ix-c，但本机实际下一跳先发给 ix-b。`endpoint` 如果填写，必须是 `next_hop` peer 上的 endpoint；`owner` peer 的 `allowed_prefixes` 用于校验前缀授权，未填写 `owner` 时等价于 `owner: <next_hop>`。

```yaml
peers:
  - id: ix-b
    domain: lab.local
    endpoints:
      - name: ix-b-tix-tcp
        address: b.example.com:7001
        transport: tix_tcp
    allowed_prefixes:
      - 10.0.1.0/24
  - id: ix-c
    domain: lab.local
    endpoints: []
    allowed_prefixes:
      - 10.0.2.0/24

routes:
  - prefix: 10.0.2.0/24
    owner: ix-c
    next_hop: ix-b
    endpoint: ix-b-tix-tcp
    policy: default-routed
    metric: 50
```

生产机恢复入口：

```bash
trustixd -config /etc/trustix/ix-a.yaml -data-dir /var/lib/trustix/ix-a -dataplane auto -cleanup-dataplane
trustixd -config /etc/trustix/ix-a.yaml -data-dir /var/lib/trustix/ix-a -dataplane auto -repair-dataplane
```

`-cleanup-dataplane-dry-run` 会读取 config 和 `<data-dir>/bpf/state.json`，输出 JSON cleanup plan 但不修改系统状态。`-cleanup-dataplane` 会按同一计划清理 TrustIX 管理的 TC clsact/filter、LAN gateway、管理 VIP、sysctl 和 TIX-TCP XDP 状态后退出；它会先拿 data-dir 锁，避免清理正在运行的实例。`-repair-dataplane` 会先执行同样的清理，再进入正常 daemon 启动流程，适合 systemd crash restart。

`config rejoin` 或其他全量替换 config log 的操作会先把旧日志保存为 `config.log.backup.<timestamp>`，默认保留最近 16 个备份。需要从备份恢复时，用 `trustixctl config restore-backup <path>`；daemon 会先完整校验备份链，并要求备份里存在当前本机 IX 的 desired event，校验通过后才替换当前 config log 并热切换 runtime。

静态 `routes[].kind` 支持 `unicast`、`local`、`blackhole` 和 `reject`。`blackhole` 会同步到 TC route map，在 fast path 直接丢包并计入 `BLACKHOLE_ROUTE`；`reject` 会计入 `tc_ingress_reject_routes`，原包由 TC 丢弃。非 RST TCP reject 会在 TC/eBPF 内直接生成 IPv4 TCP RST 并 redirect 回 LAN，暴露 `tc_reject_tcp_rst_generated` 和 `tc_reject_tcp_rst_errors`；可接收错误的 ICMP 和非 TCP/ICMP IPv4 reject 会在 TC/eBPF 内生成 IPv4 ICMP destination unreachable 并 redirect 回 LAN，暴露 `tc_reject_icmp_generated` 和 `tc_reject_icmp_errors`。TCP RST 原包和不可接收 ICMP error reply 的 ICMP 类型会在 TC 静默丢弃并计入 `tc_reject_no_reply_drops`；IPv4 分片、IPv4 options 或短包仍 capture 到 daemon 回注 LAN，并暴露 `reject_icmp_generated`、`reject_reply_errors` 等 daemon 兜底计数。`lan.mode: nat`、某个 `lans[].mode: nat` 或 policy `rewrite: snat_gateway` 会启用 IPv4 TCP/UDP/ICMP echo NAT：TC/eBPF LAN ingress fast path 会按 NAT source/route/exclude maps 把出向源地址改写为选中的 NAT LAN gateway IP，并更新 IPv4/TCP/UDP 校验和；capture event 会带回原始源地址，daemon 镜像有 TTL 和容量限制的 NAT state，并把 bindings 增量同步到 TC/eBPF。多 LAN 下当前只选择第一个 NAT LAN 作为 NAT gateway/source prefix；没有 NAT LAN 但 policy 要求 SNAT 时选择第一个带 gateway 的 LAN。NAT state 默认 `max_bindings=16384`、`binding_ttl=5m`，可用所选 NAT LAN 的 `nat.max_bindings` 和 `nat.binding_ttl` 覆盖，热更新会按新 TTL 重算现有 binding 过期时间并按新容量 LRU 淘汰。远端回包在解密后会优先走 LAN egress TC DNAT fast path，按 binding 做 DNAT并计入 `tc_nat_dnat_translations`；fast path 不可用时仍由 daemon DNAT 兜底。`status.data_path.nat` 和 BPF/datapath NAT counters 会暴露状态、TC SNAT/DNAT 命中、binding 数和错误计数。

systemd 部署文件在 `packaging/systemd/trustixd@.service`，安装脚本：

```bash
sudo scripts/install-systemd-linux.sh
sudo systemctl enable --now trustixd@ix-a
```

实例默认读取 `/etc/trustix/<name>.yaml` 和可选 `/etc/trustix/<name>.env`。卸载 systemd unit 可用 `sudo scripts/uninstall-systemd-linux.sh`；默认不会删除配置和状态目录。

后续可继续增强：

- TIX-TCP 的内核侧优化还可以继续增强：当前已有 frame/flow/crypto placement、secure offload key-install 协议、kernel crypto key map schema/status、provider-side kptr ctx-map object、可选 `trustix_crypto` `.ko`、synthetic AEAD-GCM ctx-create/roundtrip runtime probe、BPF frame seal/open、TX XDP packet seal、AF_XDP UMEM direct-build、AF_XDP native/zero-copy 协商、kernel placement in-place TX seal、AF_XDP RX UMEM direct parse、attached RX XDP frame open/replay drop/no-context deferral、64-slot replay window、embedded C eBPF XDP classifier、AF_XDP TX flow/tuple queue affinity、TX bounded backpressure、AF_XDP fast path、显式 raw socket 调试 fallback 和状态暴露。后续可以继续探索 driver/native TX hook、TC egress 可行性或更少 BPF_PROG_RUN copy 的路径。
- Web UI。

这些能力已有接口边界，后续可以在现有 package 后面继续补实现。
