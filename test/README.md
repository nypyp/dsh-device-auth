# dsh-device-auth 沙箱验收（acceptance）

`test/acceptance.sh` 在 **隔离沙箱** 里用 `--patch` overlay 挂载本插件、启动一个临时
`dsh web`（默认 `:3099`），然后对真实 HTTP 端点跑 T1–T14。它验证的是「真实 Harness
进程 + 真实 connection/BrowserAuth 代码路径」，不是进程内 fake（后者见
`test/unit.test.mjs`）。

## 安全边界（脚本自身强制）

| 约束 | 实现 |
|---|---|
| 不 stop/restart 生产 `dsh-web` | 只 kill 自己启动的 PID；启动前后对比 `:3080` 监听 pid，变化即 FAIL |
| 不写 `~/.dsh` | 只 `cp -a` 复制 `profiles` / `.credentials.yaml`（可选 `storages`）到 `/tmp` |
| 不用 `:3080` | `PORT == PROD_PORT` 直接拒绝运行 |
| 只写沙箱与 test/ | `SANDBOX` 必须是 `/tmp` 下的安全绝对路径，且不得与生产 home / `$HOME` 重叠 |
| 不误杀 | 只按 PID kill；**不用** `pkill -f`（`-f` 会匹配到脚本自身命令行） |
| 不碰插件源码 | 本脚本只读插件文件（仓库内，`PLUGIN_INDEX` 默认 `lib/index.js`） |

## 运行

```sh
./test/acceptance.sh
```

典型输出：每个用例一行 `[PASS]/[FAIL]/[SKIP]`，最后是汇总表、**生产守卫**、沙箱路径。
耗时约 1–2 分钟（两到三次 `dsh web` 启动/重启，每次约 5s 就绪）。

退出码：

- `0` 全部 PASS；或插件文件尚不存在 → 打印明确 SKIP 说明后 `exit 0`（不伪造结果）
- `1` 至少一个 FAIL（启动失败时未执行的用例也记 FAIL）
- `2` 前置条件错误（缺 `dsh`/`node`/`curl`、端口被占用、生产 home 缺失、沙箱路径不安全）

## 前置条件

- `dsh` 在 PATH（实测 `0.2.2-rc.1`），`node`（实测 `v24.22.3`），`curl`，`bash` 4+
- 生产 `~/.dsh` 存在 `profiles/web` 与 `.credentials.yaml`（只读复制）
- `:3099` 空闲；若被占用脚本直接报错退出，**不会**去杀未知进程

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `SANDBOX` | `/tmp/dsh-device-auth-sandbox` | 沙箱根目录（必须在 `/tmp` 下） |
| `PORT` | `3099` | 沙箱监听端口 |
| `PROD_PORT` | `3080` | 生产端口（仅用于守卫比对，绝不使用） |
| `PROD_DSH_HOME` | `~/.dsh` | 生产 DSH home（只读） |
| `PLUGIN_DIR` | 脚本上级目录 | 插件目录 |
| `PLUGIN_INDEX` / `PLUGIN_CLI` | `<dir>/index.js` / `<dir>/bin/dsh-auth.mjs` | 插件/命令行入口 |
| `DSH_BIN` / `NODE_BIN` / `CURL_BIN` | `command -v` | 显式指定可执行文件 |
| `COPY_STORAGES` | `1` | 是否复制 `storages`（`0` 跳过；最小 home 已验证可启动） |
| `STORAGES_MAX_MB` | `64` | 超过则跳过 `storages` 复制 |
| `WAIT_READY_SECONDS` | `60` | 等待 `/connect?token=bogus` 返回 401 的上限 |
| `ALLOW_NON_TMP_SANDBOX` | `0` | 仅为 `1` 时允许 `SANDBOX` 不在 `/tmp` 下 |

## 沙箱机制

1. **复制最小 home**：`profiles/`、`.credentials.yaml`、可选 `storages/`；**不带**
   `sessions/`、`attachments/`、`cache/`；目录 `0700`。
2. **overlay patch**（`$SANDBOX/overlay.yml`）：

   ```yaml
   - insert:
       - id: device-auth
         name: /home/nypyp/proj/default-workspace/plugins/dsh-device-auth/index.js
         config:
           storePath: /tmp/dsh-device-auth-sandbox/home/remote-auth.json
   ```

   Loader 的 `anchorInsertedPluginNames` 会把 **绝对路径** 转成 `file://` URL（已实测），
   因此不需要先 `file:` 安装到沙箱 profile 的 `node_modules`。插件 `package.json`
   含 `"type": "module"`，ESM 加载正常。
3. **写 overlay 后先跑一致性检查**：`dsh --profile web --patch <overlay> --dump-config`
   必须解析出 `device-auth` 行；`printUrl:false` 变体必须出现 `printUrl: false`。
4. **启动**：

   ```sh
   DSH_HOME=$HOME_DIR dsh --profile web --patch <overlay> --port 3099 --no-open
   ```

   ⚠️ `--patch` 是 **launcher 选项**，必须排在 `--port` / `--no-open` 等 web app 选项
   **之前**；写成 `dsh web --port 3099 --patch x.yml` 会被 web 参数解析器拒绝
   （`error: unknown option '--patch'`）。脚本里已固定正确顺序。
5. **就绪判定**：`GET /connect?token=bogus` 返回 `401`（同时进程仍存活），最多 60s。
6. **收尾**：`trap EXIT` 里 `SIGTERM` → 等端口释放（最多 10s）→ `SIGKILL` 兜底；
   保留 `$SANDBOX` 的日志、store、evidence 供排查。

## 用例与期望

| ID | 验收点 | 期望（实测 DSH 0.2.2-rc.1） |
|---|---|---|
| T1 | 未授权令牌 | `GET /connect?token=bogus` → `401` |
| T2 | 设备令牌（`dsh-auth add --json`） | `GET /connect?token=dsh_dev_…` → `302` + `Set-Cookie` + `location: ./api/remote.mux` |
| T3 | `/connect` cookie 可用性（v2 operator） | 用 T2 cookie `GET /api/` → `404`（已过鉴权，非 401） |
| T4 | 浏览器 index 流（v1 cookie） | `GET /?token=dsh_dev_…` → `303` + `Set-Cookie`；再带该 cookie `GET /` → `200` + `text/html` |
| T5 | 真实 launch token 零回归 | 从 `dsh.log` 抓 `token=…` 最后一条 → `/connect` → `302` + cookie |
| T6 | 轮换 | `dsh-auth rotate phone`：旧令牌 → `401`，新令牌 → `302` |
| T7 | 撤销 | `dsh-auth revoke phone`：该令牌 → `401`；`list --json` 中 `status=revoked` 且 `revokedAt` 非空 |
| T8 | 重启保持（R1） | `add tablet` → 杀沙箱 → 同 overlay 重启 → tablet 令牌仍 `302`（launch token 已轮换） |
| T9 | 日志/存储无明文（R4） | 三份 `dsh*.log` 无任何 `dsh_dev_…`；store 结构合法、只含 `tokenHash`（sha256 hex） |
| T10 | 文件权限 | store `0600`、其父目录 `0700` |
| T11 | Host fence 不回归 | `Host: evil.example` + 有效设备令牌 → `403` |
| T12 | `printUrl:false` 变体 | overlay 追加 `web-runtime` 覆盖后：日志无 `dsh web: http` 行、无 `token=…`；设备令牌仍 `302` |

> T12 的「T2 仍 PASS」用 **T8 重启前 mint 的 tablet 令牌** 验证：它既证明设备认证在
> `printUrl:false` 下仍工作，也再次证明 store 跨重启有效。

## 与任务书的一处语义差异（重要，避免误报）

任务书 T3 写「用 T2 cookie `GET /` → 200 text/html」，但真实 DSH（0.2.2-rc.1）语义是：

- `/connect?token=` 铸造的是 **v2 operator cookie**，只用于 `/api`；用它 `GET /` 返回
  `401` 是**设计行为**（`BrowserAuth.authorizeIndex` 只认 `/?token=` 流程铸的 **v1**
  浏览器 cookie）。
- 浏览器页面 cookie 必须先走 `/?token=<device>`：`303` + v1 cookie → `GET /` `200`。

因此脚本把 T3 实现为「v2 cookie → `/api/` 404（已鉴权）」，把 v1 → `GET /` 200 放在 T4。
这一口径已与 Lead 对齐。

## 本地实测结论（独立复核）

环境：`dsh 0.2.2-rc.1`、`node v24.22.3`、`bash 5.3.9`，生产 `:3080` pid 未变。

- `bash -n` 通过（shellcheck 未安装）。
- 沙箱启动约 **5s** 就绪（上限 60s）；最小 home（仅 `profiles` + `.credentials.yaml`，
  不带 `storages`）同样可启动（已单独验证）。
- `printUrl:false` 覆盖后日志确实没有 `dsh web: http` 行，设备令牌照常 `302`。
- 全量结果：**T1–T12 全部 PASS（12/12）**；退出后 `:3099` 无监听、无残留进程，
  生产 `dsh-web` pid 前后一致（未被重启）。
- 插件未就绪路径：用不存在的 `PLUGIN_INDEX` 运行 → 打印缺失文件清单并 `exit 0`。

## 已知限制 / 接口假设

1. **CLI 形态**（当前 `bin/dsh-auth.mjs` 支持）：`add <label> --json`、`rotate <label> --json`、
   `revoke <label> --json`、`list --json`，全局 `--store <path>`、`--origin <url>`。
   脚本显式传 `--store`/`--origin`，不会落到生产默认值。
2. **令牌格式**：`dsh_dev_<43 base64url>`（`TOKEN_PREFIX` = `dsh_dev_` + 32B base64url）。
   若未来改 `prefix` 配置，`extract_token` 的正则需同步。
3. **store 路径**：固定 `$HOME_DIR/remote-auth.json`，父目录即沙箱 home；T10 校验
   store `0600` + 父目录 `0700`（CLI 的 `writeStoreFile` 会 chmod 目录 `0700`）。
4. **overlay 用绝对路径** 插入 `index.js`，假定插件目录自带 `package.json`（含
   `"type": "module"`）。若改为以包名 `dsh-device-auth` 安装，需先把它装进沙箱 profile。
5. **T5 依赖 `printUrl` 打开**（base overlay 不覆盖 `web-runtime`）。若插件 bundle patch
   先行关闭 `printUrl`，T5 会 **SKIP** 并说明原因，而不是 FAIL。
6. **不覆盖**「撤销后已签发的 30 天 cookie 立即失效」：当前 DSH cookie 不含设备 id，
   撤销只阻止再次换取 cookie（见插件 README「已知边界 1」），不属本脚本范围。
7. 不测试 DSH Go 客户端 / 隧道真实连接；只验证 HTTP 契约与进程内行为。
8. 不做跨 DSH 版本兼容矩阵：版本漂移导致端点语义变化时，脚本会以 FAIL + 原始
   证据（`evidence/*.hdr|.body`）暴露，而非静默通过。

## 产物与清理

脚本退出后保留沙箱：

```text
/tmp/dsh-device-auth-sandbox/
├── overlay.yml                       # base overlay
├── overlay-printurl-false.yml        # T12 变体
├── dsh.log                           # 基线进程
├── dsh-restart.log                   # T8 重启进程
├── dsh-printurl-false.log            # T12 变体进程
├── home/                             # 复制的最小 DSH home（含 remote-auth.json）
└── evidence/                         # 每个请求的 .hdr/.body、CLI 输出、dump-config
```

手动清理：`rm -rf -- /tmp/dsh-device-auth-sandbox`。

> `evidence/` 与 `cli-*.out` 含 **明文设备令牌**（这是 `add`/`rotate` 显式输出的一次性
> 令牌）；仅用于本地排查，不要保留在共享环境。store 本身只含哈希。


## 0.2.0 新增用例

| ID | 断言 | 期望 |
|---|---|---|
| T13 | 撤销设备后，用该设备**已签发的 `/connect` cookie** 再请求 `/api/` | 401（撤销前为 404） |
| T14 | 撤销设备后，用该设备**已签发的浏览器 cookie** 请求 `/` | 401（撤销前为 200） |

这两项验证 R3 的「撤销即时生效」：不仅旧设备令牌不能再换取 cookie，已经拿到的会话 cookie 也在下一次请求被拒绝。实现见 `lib/sessions.mjs`（cookie→设备索引，仅存哈希）。
