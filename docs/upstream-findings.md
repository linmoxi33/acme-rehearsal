# 上游实测记录：certbot 5.8.0

所有结论都对应到具体文件与行号，源码取自
`codeload.github.com/certbot/certbot/tar.gz/refs/tags/v5.8.0`。

---

## 1. `--dry-run` 到底做了什么

### 1.1 强制改指向 staging

`certbot/src/certbot/_internal/cli/cli_utils.py:270-286`：

```python
default_servers = (flag_default("server"), constants.STAGING_URI)

if config.staging and config.server not in default_servers:
    raise errors.Error("--server value conflicts with --staging")

if config.server == flag_default("server"):
    config.server = constants.STAGING_URI
    ...
if config.dry_run:
    if verb not in ["certonly", "renew", "reconfigure"]:
        raise errors.Error("--dry-run currently only works with the "
                           "'certonly' or 'renew' subcommands (%r)" % verb)
    config.break_my_certs = config.staging = True
```

`constants.py:134`：

```python
STAGING_URI = "https://acme-staging-v02.api.letsencrypt.org/directory"
```

**结论**：`--dry-run` 不是"本地模拟"，是"把请求发到另一个真实服务器"。离网环境不可用。

### 1.2 仍然要真实完成挑战

`client.py:503-541` 与 `client.py:407` 显示，`dry_run` 只影响"是否保存证书"和"是否跑 hook"，**不影响授权流程**。也就是说 HTTP-01 的 `/.well-known/acme-challenge/<token>` 仍然要被真实访问到。

这要求：

- 域名真的解析到执行机；
- 80 端口可达（或 443，若用 TLS-ALPN-01）；
- 中间没有拦截。

本地测试域名（`demo.test`、`localhost`）无法满足。

### 1.3 会真实注册账户、真实下单

`client.py:195-205`：

```python
if config.dry_run:
    config.email = None
...
regr = perform_registration(acme, config, tos_cb)
acc = account.Account(regr, key)
account_storage.save(acc, acme)
```

即使 dry run，账户也会被创建并写入 `accounts/`。订单同理。

### 1.4 跳过全部 deploy hook

`hooks.py:234-240`：

```python
if dry_run and not run_deploy_hooks:
    logger.info("Dry run: skipping deploy hook command: %s", command)
    return
```

`run_deploy_hooks` 默认 `False`。所以"续期后重启服务"这一环在 dry run 里**永远不可见**——而这一环恰恰是生产事故的高发区（配置写错、服务起不来、权限不对）。

### 1.5 成功后不落任何证书

`main.py:635-637`（`_report_new_cert`）：

```python
if config.dry_run:
    display_util.notify("The dry run was successful.")
    return
```

`main.py:688` 的 `_csr_report_new_cert` 同样如此。

**这是教学上的硬伤**：`--dry-run` 的终点是一句话。学员拿不到 `cert.pem`，看不到链结构，没法验证 SAN，也没法把它挂到测试服务器上。

---

## 2. 官方集成测试的门槛

`certbot-ci/src/certbot_integration_tests/utils/acme_server.py`：

```python
from certbot_integration_tests.utils import pebble_artifacts
...
pebble_artifacts_rv = pebble_artifacts.fetch(self._workspace, self._http_01_port)
pebble_path, challtestsrv_path, pebble_config_path = pebble_artifacts_rv
...
[challtestsrv_path, '-management', ':{0}'.format(CHALLTESTSRV_PORT), ...]
[pebble_path, '-config', pebble_config_path, '-dnsserver', dns_server, '-strict']
```

`conftest.py:22-25` 还提供 `--dns-server {bind,challtestsrv}` 开关。

**结论**：上游要闭环，需要两个 Go 二进制（Pebble + challtestsrv）、一个 DNS 服务器选择、以及端口编排。这套东西对 CI 是合理投入，对"课堂上讲清楚 ACME"过重。

本项目用纯 Python 实现了同等能力的一个子集，代价是不支持通配符和 TLS-ALPN-01（见 `docs/limits.md`）。

---

## 3. 顺带发现的格式事实

`renewal/*.conf` **不是合法 INI**。certbot 把 `version`、`archive_dir`、`cert`、`privkey`、`chain`、`fullchain` 写在**任何 section header 之前**：

```
# renew_before_expiry = 30 days
version = 5.8.0
archive_dir = /etc/letsencrypt/archive/example.com
cert = /etc/letsencrypt/live/example.com/cert.pem
...

[renewalparams]
account = ...
authenticator = nginx
server = https://acme-v02.api.letsencrypt.org/directory
```

Python 标准库 `configparser` 读到第二行就抛 `MissingSectionHeaderError`。certbot 自己用的是 `configobj`（允许顶层键）。

本项目的 `store._parse_renewal_config` 因此写了一个专用解析器，而不是套 `configparser`。这个坑在开发时真实踩到过一次（首版用 `configparser`，`store.get()` 直接崩）。

---

## 4. 未验证的部分

- **staging 的配额具体数值**：官方文档给的是"比生产宽松"，本项目在 `preview` 里只引用**生产**的公开限制（每注册域名每周 50 张、重复证书每周 5 张），不猜测 staging 的具体数字。
- **不同 CA 的错误码差异**：本项目只实现 RFC 8555 注册过的错误 URN 子集，不模拟 ZeroSSL / Buypass 的私有行为。
- **certbot 5.8.0 之后的行为变化**：结论以 v5.8.0 标签为准。
