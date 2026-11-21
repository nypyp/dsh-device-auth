# dsh-device-auth

> 给 DeepSeek Harness Web UI 增加**稳定、可按设备撤销**的登录令牌：`dsh web` 重启后，已配对客户端不用再复制一次 43 位随机 launch token。

[![ci](https://github.com/nypyp/dsh-device-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/nypyp/dsh-device-auth/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-MIT-2e8b57)
![dsh](https://img.shields.io/badge/dsh-%3E%3D0.2.2--rc.1%20%3C0.3.0--0-4d6bfe)
[English](README.en.md)

## 为什么

DeepSeek Harness 的 Web 启动令牌（launch token）由进程在每次启动时随机生成，只通过启动日志打印一次。任何第三方远程客户端（DSH Go、脚本、其它设备）都必须保存它，因此每次重启或开机后：

- 所有已配对客户端立即失效，只能人工从 `journalctl` 重新复制一串 43 位随机字符；
- 没有"固定、轮换、按设备撤销"这一层，也无法避免令牌明文进日志。

`dsh-device-auth` 在 **profile 层**补上这一层，**不修改任何 DSH 安装包**，也不会在 `dsh` 升级时丢失。

## 特性

- **稳定**：每台设备一条长期令牌，`dsh web` 重启、机器重启、`npm i -g @deepseek-ai/dsh@新版本` 都不需要重配。
- **可轮换**：同一设备重新签发即原地轮换，旧令牌下一个请求立即 401。
- **按设备、撤销即生效**：`dsh-auth list / revoke`，一台设备一个凭据；撤销后该设备**已经拿到的 cookie 也在下一次请求被拒绝**（不只是不能再换取）。
- **不落日志**：bundle 层关闭启动 URL 打印；令牌只在显式 `dsh-auth add|rotate` 时显示一次。
- **零回归**：只在设备令牌命中时把请求交回原实现；原 `/?token=`、302/303、30 天签名 cookie、Host/Origin fence、`--trusted-host`、`--public-url` 全部保持原行为。
- **自包含**：没有运行时依赖、没有构建步骤；服务端只保存 SHA-256 哈希。

## 安装

### 插件管理（Web / Desktop）

在 **插件 → 添加插件** 里搜索 `dsh-device-auth` 并安装，然后重启 `dsh web`。

### 命令行

```sh
# 发布到 npm 后
dsh plugin --profile web add -w dsh-device-auth

# 从本地目录安装（开发调试）
dsh plugin --profile web add -w file:/absolute/path/to/dsh-device-auth

systemctl --user restart dsh-web   # 或按你的部署方式重启
```

安装后插件所在的 bundle 层会同时把 `web-runtime.printUrl` 设为 `false`：启动日志不再出现带真实令牌的 URL。

## 使用

```sh
dsh-auth add phone --kind dsh-go        # 给手机签发（令牌只显示一次）
dsh-auth add laptop --kind browser      # 给浏览器签发
dsh-auth list                           # 设备清单：label / id / 状态 / 时间
dsh-auth rotate phone                   # 轮换：旧令牌立即失效
dsh-auth revoke phone                   # 撤销单设备
dsh-auth revoke --all                   # 撤销全部
dsh-auth purge                          # 清理已撤销记录
```

`add` / `rotate` 会打印三种形式，按客户端类型选一种：

```
token (shown once): dsh_dev_…
app connect link:   http://127.0.0.1:3080/connect?token=dsh_dev_…
browser login link: http://127.0.0.1:3080/?token=dsh_dev_…
```

- **DSH Go / SSH 隧道客户端**：把 `dsh_dev_…` 填进主机配置的「DSH 登录令牌」。隧道本地端口变化不影响，客户端每次重连都用同一令牌换新 cookie。
- **浏览器**：直接打开 `browser login link`（把 origin 换成你的公网地址，例如 `https://dsh.example.com/?token=dsh_dev_…`），之后走正常的 30 天 cookie。

CLI 默认读写 `$DSH_HOME/remote-auth.json`（未设置时为 `~/.dsh/remote-auth.json`），可用 `--store` 指定；`--origin` 只影响打印出来的链接。

## 工作原理

```
客户端 ──► GET /connect?token=dsh_dev_<43>
              │
              ├─ 命中设备表？── 否 ──► 原样交给 client-connection（真实 launch token / 错误令牌行为不变）
              │
              └─ 是 ──► 把 token 换成本进程真实 launch token
                          └─► 原 authorizeConnect：302 + 30 天签名 cookie（authority 绑定、Host/Origin fence 不变）
```

- 插件包装 `connection` 服务的 `authorizeConnect` / `authorizeIndex`（两者在请求时被动态调用），只对以 `dsh_dev_` 开头且命中设备表的令牌生效；
- 真实 launch token 通过公开服务方法 `authenticatedUrl()` 读取，不改造、不替换；
- 设备表只读：插件不写文件，轮换/撤销由 CLI 在跨进程锁下原子写入，因此不存在"旧快照复活已撤销设备"；
- 撤销即时生效：插件把设备交换签发的 cookie 以 SHA-256 记入 `remote-auth-sessions.json`（同样 0600、只存哈希），并包装 `admit` / `authorizeIndex`——命中已撤销设备的 cookie 直接 401；真实 launch token 的 cookie 不在索引里，原样委托（零回归）。

更细的机制、威胁模型与升级策略见 [docs/DESIGN.md](docs/DESIGN.md)。

## 配置

```yaml
# 在 profile 的 cordis.patch.yml（或你的 bundle patch）中
- id: device-auth
  config:
    storePath: !!js dshHomePath('remote-auth.json')  # 必填：设备表路径
    prefix: dsh_dev_                                  # 可选：令牌前缀
```

## 兼容性

| 项 | 值 |
|---|---|
| DSH | `>=0.2.2-rc.1 <0.3.0-0`（已在 `0.2.2-rc.1` 实测） |
| Node | `>=24.9.0`（跟随 DSH Web 运行时） |
| 平台 | Web / Desktop profile（Host 插件，无客户端 UI） |

插件会在激活时显式探测所需服务方法；未来 DSH 若改动这两个方法，**插件会启动失败并报错**，而不是静默放行。升级前请查看 [CHANGELOG.md](CHANGELOG.md) 与本仓库 CI。

## 已知边界

1. **撤销即时生效的范围**：插件把「设备交换时签发的 cookie」以哈希建立了索引，撤销后这些 cookie 的下一次请求即 401（`/api` 与浏览器页面都覆盖）。但有两类 cookie 无法归属到设备：① 用真实 launch token 登录的 owner 会话；② 插件安装/升级前就已签发的旧 cookie。它们不受设备撤销影响，直到过期。若会话索引文件丢失，上述 cookie 会退回"交给原鉴权"的行为（不会误拒合法会话，但也不会踢掉对应设备）。
2. 所有设备都是 owner 级权限——DSH 没有 per-device 权限模型，本插件的"按设备"只到凭据维度。
3. 设备令牌在客户端侧明文保存（手机安全存储 / DSH Go 配置）；服务端只存哈希。
4. 未实现一次性配对码（DSH Go 只会用 `token=` 换取，没有配对码消费者）。

## 开发与测试

```sh
npm test               # 单元测试（无依赖，不需要 DSH）
npm run check          # node --check + bash -n
./test/acceptance.sh   # 隔离沙箱端到端验收（自建临时 DSH_HOME，:3099，不碰生产）
```

`test/acceptance.sh` 会复制一份最小 `$HOME/.dsh` 到 `/tmp`，用 `--patch` overlay 把本插件挂进临时 `dsh web`，验证 T1–T12（未授权、设备令牌、cookie、轮换、撤销、重启保持、Host fence、日志卫生、`printUrl:false` 等）。它**绝不** stop/restart 生产服务，也**绝不**写 `~/.dsh`。

## 回滚

```sh
dsh plugin --profile web remove dsh-device-auth   # 或 plugin_manager remove_bundle
# 同时删除 profile 里的 bundle 选择项，然后重启 dsh web
```

回滚后行为回到基线（随机 launch token、启动 URL 照常打印）；`~/.dsh/remote-auth.json` 可保留或删除。

## 参考与致谢

设计参考了 [OpenChamber](https://github.com/openchamber/openchamber) 的设备凭据模型（不透明 bearer、服务端只存 SHA-256、同设备重发即轮换、按设备撤销）。感谢其 MIT 开源实现为这套方案提供了可直接对照的工程先例。

## License

[MIT](LICENSE)
