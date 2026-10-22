## 在离线的盒子里，把 ACME 走一遍

`certbot --dry-run` 看起来解决了「先试一次」的需求，但它强制把请求发往真实的 Let's Encrypt staging、必须完成真实挑战、跳过全部部署钩子，成功后**不落任何证书**——只打印一句 `The dry run was successful.`。离网环境不可用，教学过程看不见。

这个版本提供一个**离线、可重复、过程可见、能自证没有副作用**的排练场。

### 包含什么

- **迷你 ACME 服务端**（RFC 8555 子集）：`directory` / `new-nonce` / `new-account` / `new-order` / `authz` / `chall` / `finalize` / `cert` / `revoke-cert`，flattened JWS（RS256 / ES256）、一次性 nonce、`url` 绑定、POST-as-GET、`application/problem+json`
- **真 X.509 签发**：沙盒内两级 CA（根 → 中间 → 叶子），`chain.pem` 与 `fullchain.pem` 是两份真实文件
- **真实的 HTTP-01 往返**：服务端真的连 `127.0.0.1:<port>` 并带 `Host:` 头，只有 DNS 解析走沙盒路由表
- **certbot 兼容布局**：`live/` + `archive/` + `renewal/*.conf`，含那个不合 INI 规范的顶层键格式
- **只读影响面预演**：对真实 `/etc/letsencrypt` 算出 `renew` / `revoke` / `delete` / `expand` 会做什么，一个字节都不改
- **6 个场景**，含 3 个故障注入（挑战响应错误、配额耗尽、CSR 越权）

### 隔离是被算出来的

每次运行都产出 `verdict.checks`：

| 检查 | 证据 |
|---|---|
| `no_egress` | socket 层拦截，被拦截数必须为 0，放行的连接目标必须是 loopback |
| `sandbox_writes_only` | 每次写入 `Path.resolve()` 后必须落在沙盒根内 |
| `real_config_untouched` | 真实配置目录前后全树 sha256 快照必须完全一致 |
| `chain_verifies` | 逐级验签 + 系统 `openssl verify` 独立复核 |
| `no_public_ca_contact` | 已知公共 CA 主机名在解析前就被拒绝 |

### 实测

- **217 passed / 2 skipped**（跳过项为 Windows 无符号链接权限）
- **92%** 语句覆盖（2656 语句 / 225 未覆盖）
- **21 个变异体全部被杀死，0 存活**（判定按失败用例集合差集，不按数量）
- `ruff check` 全绿
- HTML 报告 DOM 探针 13 项断言通过，正文对比度 15.1:1

### 安装

```
pip install acme-rehearsal-0.1.0-py3-none-any.whl
acme-rehearsal demo --workdir ./demo
```

未发布到 PyPI。`pip install acme-rehearsal` 会 404，请用下方资产。

### 边界

不替代 certbot：无 Apache/Nginx 插件、无 DNS 服务商 API、不支持通配符、无 TLS-ALPN-01。`EgressGuard` 只覆盖当前进程。详见 `docs/limits.md`。

线上源码与本地工作树做过 39 个 blob 的逐字节比对，零差异。
