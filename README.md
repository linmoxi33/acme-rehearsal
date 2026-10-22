# acme-rehearsal

[![CI](https://github.com/linmoxi33/acme-rehearsal/actions/workflows/ci.yml/badge.svg)](https://github.com/linmoxi33/acme-rehearsal/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/linmoxi33/acme-rehearsal)](https://github.com/linmoxi33/acme-rehearsal/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**在完全离线的沙盒里，把 ACME 证书的签发、续期、吊销完整排练一遍——包括每一步的输入、输出和证据。**

围绕 [`certbot`](https://github.com/certbot/certbot)（EFF，Apache-2.0，5.8.0）的真实语义构建。不 fork 它的代码，而是复刻它面对的那套协议，然后把整个过程关进一个能证明"什么都没漏出去"的盒子里。

```
建 CA → 起服务端 → 注册 → 下单 → 过挑战 → 签发 → 验证链 → 落盘 → 判定
```

---

## 为什么需要这个

证书操作有三个特点，正好是最不适合"直接在生产上试"的那一类：**要花钱、会闯祸、看不见过程**。

`certbot` 自带 `--dry-run` 和 `--staging`，看起来已经解决了"先试一次"的需求。实测下来，它们的边界比名字暗示的窄得多。

### 上游 `--dry-run` 的实测边界

在 `certbot` 5.8.0 源码里逐条核对（`cli/cli_utils.py:281`、`client.py:195`、`main.py:635`、`hooks.py:238`）：

| 事实 | 位置 | 后果 |
|---|---|---|
| `--dry-run` 强制把 server 改写成 `https://acme-staging-v02.api.letsencrypt.org/directory` | `cli_utils.py:276-281` | 必须有公网出口，离线教室、气隙环境、CI 沙箱里跑不了 |
| 仍然要真实完成 ACME 挑战 | `client.py:503-541` | 需要真实域名解析到本机、80/443 可达；本地 `demo.test` 不行 |
| 会真实注册 staging 账户、真实下单 | `client.py:195-205` | 消耗 staging 配额；账户被写进 `accounts/` |
| 跳过全部 deploy hook | `hooks.py:238` | "续期后重启 nginx"这一段永远演示不到 |
| 成功后**不落任何证书文件** | `main.py:635-637` | 只打印一句 `The dry run was successful.`，学员看不到签出来的东西 |

最后一条是教学上最致命的：`--dry-run` 的成功画面后面什么都没有。没有 `cert.pem`，没有链，没有 `live/` 目录，没有可复制的部署产物。

### 官方自己的闭环测试需要什么

`certbot-ci/src/certbot_integration_tests/utils/acme_server.py` 里，要跑通一次完整签发，需要：

- 下载并运行 **Pebble**（Let's Encrypt 用 Go 写的测试 CA）二进制；
- 再起一个 **challtestsrv** 来管理 DNS 和 HTTP-01 的响应；
- 指定 `--dns-server {bind,challtestsrv}`，配置端口映射。

也就是说，连上游自己都认为"要闭环就得先搭一套外部服务"。这个门槛对 CI 是合理的，对"讲清楚 ACME 到底怎么跑"就太重了。

### 缺口

不是"certbot 缺一个 dry-run"，而是缺一个**离线、可重复、能看见每一步、并且能自证没有副作用**的排练场。本项目的全部价值就在这个"自证"上。

---

## 它做什么

一个沙盒，四件事：

**1. 真的 ACME，不是假装的**

内置一个 RFC 8555 子集的服务端：`directory` / `new-nonce` / `new-account` / `new-order` / `authz` / `chall` / `finalize` / `cert` / `revoke-cert`。每次 POST 都是 flattened JWS，nonce 一次性，`url` 头必须匹配请求地址（防重放），读资源必须走 POST-as-GET。错误响应是 `application/problem+json` 加注册过的错误 URN。

**2. 真的证书，不是占位符**

沙盒内现场生成两级 CA（根 → 中间 → 叶子），签出的是**真 X.509**：能被 `openssl x509` 读、能被 `openssl verify` 独立验链。`chain.pem` 和 `fullchain.pem` 是真的两份不同文件，不是同一个字节复制两遍。

**3. 真的 HTTP 往返，只有 DNS 是模拟的**

HTTP-01 验证时，**服务端真的发起 TCP 连接**到 `127.0.0.1:<port>` 并带上 `Host: <域名>` 头。只有"域名 → 地址"这一步查的是沙盒路由表。所以学员看到的失败形态和真实环境一致：404、body 不匹配、连接被拒，各有各的报错。

**4. 真的 certbot 目录结构**

产物是 `live/` + `archive/` + `renewal/*.conf`，字段名和顺序对齐 certbot 自己的输出。`renewal/*.conf` 能被本项目的解析器读回（注意：certbot 的这个格式**不是合法 INI**——顶层键写在任何 section 之前，`configparser` 直接拒绝）。

---

## 隔离是怎么被证明的

不是写在文档里"我们很安全"，而是每次运行都算一遍，结论放在 `verdict.checks` 里：

| 检查项 | 证据来源 |
|---|---|
| `no_egress` | 在 socket 层拦截 `getaddrinfo` / `connect` / `connect_ex` / `create_connection`；被拦截次数必须为 0，且所有放行的连接目标必须是 loopback |
| `sandbox_writes_only` | 每一次写都过路径前缀校验，`Path.resolve()` 之后必须落在沙盒根内（能挡住 `../` 和指向外部的符号链接） |
| `real_config_untouched` | 传入真实 `--config-dir` 时，前后各做一次全树 sha256 快照，逐文件比对必须完全一致 |
| `chain_verifies` | 叶 → 中间 → 根逐级验签，另外再跑一次 `openssl verify` 做独立复核 |
| `no_public_ca_contact` | 已知公共 CA 主机名在**解析之前**就被拒绝，所以改 hosts 文件也绕不过去 |

任何一项不通过，`verdict.passed` 就是 `false`，进程退出码为 1。这个判定是**算出来的**，不是写死的。

---

## 快速开始

```bash
pip install -e .

# 一次完整签发，产物在 ./rehearsal/
acme-rehearsal run --scenario issue --workdir ./rehearsal

# 签发 + 续期（先签一张 1 天有效期的，让 renew 的判定真的触发）
acme-rehearsal run --scenario renew --workdir ./rehearsal

# 只读预演：对真实 /etc/letsencrypt 算出"会发生什么"，一个字节都不改
acme-rehearsal preview --config-dir /etc/letsencrypt --operation delete

# 六个场景全跑一遍，生成带索引的 HTML 报告
acme-rehearsal demo --workdir ./demo
```

跑完会得到两样东西：

- `transcript.json` —— 每一步的输入、输出、耗时、状态、证据
- `report.html` —— 单页报告，自包含，无外部请求，可直接投屏或打印

```
rehearsal/
├── transcript.json
├── report.html
└── sandbox/
    ├── ca/                          # 根 CA + 中间 CA（私钥只在本目录）
    └── etc/
        ├── live/demo.example.test/  # cert.pem chain.pem fullchain.pem privkey.pem
        ├── archive/demo.example.test/
        └── renewal/demo.example.test.conf
```

---

## 六个场景

| 场景 | 演示什么 |
|---|---|
| `issue` | 从零到一张可部署的证书，17 个可检查的步骤 |
| `renew` | 到期判定 → 续期 → `archive/` 版本递增（`cert1.pem` → `cert2.pem`） |
| `revoke` | 吊销 → CRL 生成 → 二次吊销被拒（`alreadyRevoked`） |
| `failure-http01` | 挑战响应内容错误 → `unauthorized`，同时证明失败路径也是隔离的 |
| `failure-ratelimit` | 配额耗尽 → `rateLimited`（429），在 `new-order` 阶段就断，不进验证 |
| `failure-badcsr` | CSR 夹带未授权域名 → `badCSR`，且**一张证书都不会落盘** |

失败场景不是"演示报错"，而是**注入故障并断言预期错误真的出现了**（`expected_error_observed`）。故障没注入成功，场景就算失败。

---

## 只读预演

`preview` 子命令面对的是**真实**配置目录，全程只读：

```
$ acme-rehearsal preview --config-dir /etc/letsencrypt --operation delete
配置目录  /etc/letsencrypt
lineage   2 个
  · example.com          剩余 12 天  阈值 30 天  链接 symlink
  · api.example.com      剩余 71 天  阈值 30 天  链接 symlink

操作      delete  (风险: high)
结论      2 lineage(s) would be deleted, 27 path(s) removed
  → example.com
  → api.example.com
将触碰    27 个路径
  - /etc/letsencrypt/live/example.com/cert.pem
  ...
  ! deleting a lineage also deletes its private key; if no backup exists
    the certificate cannot be reinstalled

本次预演为只读：未创建、修改或删除任何文件。
```

它会算：哪些 lineage 落在续期窗口内、`--force-renewal` 会消耗多少配额、hook 将收到什么环境变量、哪些路径会被删。还会给出诊断警告——生产端点、`live/` 是复制而非符号链接（续期后不会更新）、`chain.pem` 为空、`manual` 认证器没有 hook（无人值守续期必挂）。

---

## 边界

这个项目**不做**以下事情，写在这里是为了避免误用：

- **不是 certbot 的替代品。** 没有 Apache/Nginx 插件，没有 DNS 服务商 API，没有 EAB、key rollover、ARI。真实签发请用 certbot。
- **不支持通配符。** `*.example.com` 会被 `rejectedIdentifier` 明确拒绝，而不是悄悄降级成普通域名。
- **DNS-01 是查表，不是查 DNS。** 记录存在沙盒内存里，因为 DNS 本身就是查表；但它不会验证你的权威服务器配置对不对。
- **不验证 TLS 握手。** 只实现 HTTP-01 与 DNS-01，没有 TLS-ALPN-01。
- **`EgressGuard` 只覆盖当前进程。** 它 patch 的是本进程的 socket 模块；沙盒从不派生具备联网能力的子进程。如果你在沙盒里调用自己的联网代码，需要自己确认它没起子进程。
- **Windows 上 `live/` 可能是复制而非符号链接。** 创建符号链接需要开发者模式或管理员权限。降级会记录在 `link_mode` 字段并写进报告，不会静默发生。

更多见 [`docs/limits.md`](docs/limits.md)。

---

## 与 certbot 的关系

本仓库**不含** certbot 源码。它只在行为层面参照 certbot：

- `live/` / `archive/` / `renewal/` 的目录布局与字段命名；
- `renewal/*.conf` 的实际格式（含那个不合 INI 规范的顶层键写法）；
- `--dry-run` 与 `--staging` 的真实语义，用于说明本项目的差异点。

`LICENSE` 是 Apache License 2.0 原文，取自 certbot 仓库（sha256 一致）。上游版权声明见 [`NOTICE`](NOTICE)。

---

## 实测结果

| 项目 | 结果 |
|---|---|
| 测试 | **217 passed / 2 skipped**（跳过项为 Windows 无符号链接权限时的两个用例） |
| 语句覆盖 | **92%**（2656 语句 / 225 未覆盖） |
| 变异测试 | **21 个注入缺陷，21 个被杀死，0 存活** |
| 场景 | 6 个全部通过，含 3 个故障注入场景 |
| 静态检查 | `ruff check` 全绿 |
| 证书链 | 自研验签器 + 系统 `openssl verify` 双重通过 |
| HTML 报告 | DOM 探针 13 项断言通过，正文对比度 15.1:1（WCAG AA 要求 4.5:1） |

变异测试覆盖的缺陷类型：关闭公共 CA 拒绝列表、把所有目标当 loopback、关闭写范围校验、让快照比对恒为"一致"、还原 thumbprint 双重编码、让 nonce 可重用、去掉 JWS 的 url 绑定、吞掉签名验证失败、让 authz 返回 URL 而非对象、允许未就绪订单 finalize、允许 CSR 夹带未授权域名、关闭限流、关闭链签名校验、让吊销不记录、让 archive 版本不递增、让续期阈值恒为 0、让三个 verdict 检查恒为真、去掉客户端 badNonce 重试。

---

## 开发

```bash
pip install -e ".[dev]"
pytest -q                                   # 全部测试
ruff check src tests tools                 # 静态检查
python tools/mutate.py --json-out mut.json  # 变异测试（约 10 分钟）
python tools/visual_check.py out/report.html --shot out/report.png
```

`tools/visual_check.py` 用浏览器实际计算的样式做断言：区块高度非零、卡片数与 transcript 一致、无横向溢出、正文对比度达到 WCAG AA。它同时输出截图供人工复核——探针证明"结构对"，截图证明"看起来对"，两者不能互相替代。

变异测试的判定规则是**比失败用例集合的差集**，不是比失败数量。一个让 A 挂掉又让 B 通过的变异体不算被杀死。
