# 边界与不做的事

写清楚"做不到什么"，比宣传"能做什么"更能防止误用。

---

## 协议覆盖

**已实现**（RFC 8555 子集）：

- `directory`、`new-nonce`、`new-account`、`new-order`、`order`、`authz`、`chall`、`finalize`、`cert`、`revoke-cert`
- flattened JWS（RS256 / ES256），nonce 一次性，`url` 头绑定
- POST-as-GET
- `application/problem+json` + 注册过的 ACME 错误 URN
- HTTP-01、DNS-01
- 吊销与 CRL 生成

**未实现**：

| 缺什么 | 影响 |
|---|---|
| `key-change` | 无法排练账户密钥轮换 |
| External Account Binding (EAB) | 无法排练 ZeroSSL / Google 这类要求 EAB 的 CA |
| ARI（RFC 9773） | 无法排练"CA 建议提前续期" |
| TLS-ALPN-01 | 只有 HTTP-01 和 DNS-01 |
| 通配符 `*.example.com` | 会返回 `rejectedIdentifier`，明确拒绝而非降级 |
| IP 标识符 | 只支持 `type: "dns"` |
| CAA 检查 | 不模拟 CAA 记录导致的拒绝 |
| OCSP | 只出 CRL，不出 OCSP 响应 |

---

## 网络模型

**HTTP-01 是真的。** 服务端确实发起 TCP 连接到 `127.0.0.1:<port>`，带 `Host: <域名>` 头，读响应体并比对 key authorization。失败形态（404、body 不匹配、连接被拒）与真实环境一致。

**DNS-01 是查表。** 记录存在内存里。DNS 本身是查表协议，所以这是忠实建模而不是偷懒；但它**不会**验证你的权威服务器配置、TTL、传播延迟。

**没有 TLS。** 沙盒的 ACME 端点走 `http://127.0.0.1`。加 TLS 意味着要维护一个信任库，会让"讲清楚 ACME 机制"这件事被证书配置淹没。

---

## 隔离保证的范围

`EgressGuard` 通过 patch **当前进程**的 `socket` 模块生效：

- `socket.getaddrinfo`
- `socket.socket.connect` / `connect_ex`
- `socket.create_connection`

它**不能**约束：

- **子进程**。沙盒本身从不派生联网子进程（`openssl verify` 不联网），但如果你在沙盒作用域内调用自己的联网代码并起子进程，那部分不受保护。
- **非 socket 的出站**。例如通过已打开的文件描述符、共享内存、或 `os.system` 调起的 curl。
- **原始 socket**。`AF_PACKET` / raw socket 绕过 `connect`。

这些限制不影响本项目的实际用法（沙盒代码全是自己写的、只有 loopback 调用），但如果要把 `EgressGuard` 当通用沙盒用，需要知道边界在哪。

已知的绕过方式在 `tests/test_guard.py` 里没有覆盖，因为覆盖它们需要真的发包。

---

## 文件系统

`FilesystemGuard` 用 `Path.resolve()` 之后做前缀比较，因此能挡住：

- `../` 逃逸
- 指向根外的符号链接（先解析再比较）

它**不能**挡住：

- 硬链接（`resolve()` 不会解开硬链接）
- 已经打开的、指向外部的文件句柄
- Windows 上的 junction / mount point 在某些边界情况下的行为差异

`enforce=False` 只用于 `preview` 的只读场景。

---

## 平台差异

| 现象 | 原因 | 项目如何处理 |
|---|---|---|
| `live/*.pem` 是复制而非符号链接 | Windows 创建符号链接需要开发者模式或管理员权限 | 降级为复制，记录 `link_mode="copy"`，写进报告并给出提示。**不静默发生。** |
| `live/` 为复制时，续期后内容会过期 | certbot 续期是替换符号链接目标；复制不会跟着变 | `preview` 会对这种 lineage 给出明确警告 |
| 路径分隔符出现在 `renewal/*.conf` | Windows 路径带反斜杠 | 解析器按 `Path` 处理，不做字符串比较 |

---

## 不是 certbot 的替代品

这个项目**不签发**能用于生产的证书：

- 根 CA 每次运行现场生成，私钥只存在沙盒目录里；
- 证书链只在沙盒内可信，任何外部客户端都不会信任它；
- 没有 ACME 账户的真实注册，没有速率限制的真实配额。

要真实证书，请用 certbot。这个项目的作用是让你在碰真实证书之前，先把流程走熟。

---

## 预演（preview）的精度

`preview` 模拟的是 certbot 的**决策逻辑**，不是它的全部行为：

- 续期窗口读的是 `renew_before_expiry` 注释行（certbot 的实际默认是证书生命周期的 1/3，本项目按 30 天处理，这是 certbot 在 90 天证书下的常见默认值）；
- 配额估算引用的是**公开的生产限制**，不包含账户当前的真实用量（沙盒不可能知道）；
- `files_touched` 列出的是"按当前目录结构推断会被写到的路径"，不包含插件可能额外改动的配置（比如 nginx 的 `sites-enabled`）。

因此 `preview` 的结论应当读作"基于目录现状的合理推断"，而不是"确定会发生这些"。

---

## 报告与截图

`tools/visual_check.py` 断言的是**渲染结果的结构性质**（区块非零高度、卡片数量、无横向溢出、对比度达到 WCAG AA），并输出截图。

探针证明"结构对"，截图证明"看起来对"。两者都不能单独当作验收——一个元素可以有正确的尺寸和对比度，但内容错位；也可以看起来正常，但关键区块 `height: 0`。本项目两个都跑。
