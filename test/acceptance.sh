#!/usr/bin/env bash
# =============================================================================
# dsh-device-auth — 隔离沙箱验收脚本（acceptance）
#
# 在 /tmp 下复制一份最小 DSH home，用 `--patch` overlay 把本插件挂进一个
# 临时 `dsh web`（端口 3099），然后对真实 HTTP 端点跑 T1–T12 验收。
#
# 安全边界（脚本自身强制）：
#   * 绝不 stop/restart 生产 dsh-web（systemd --user，:3080）；
#   * 绝不写入 ~/.dsh（只 read/cp 复制到 /tmp 沙箱）；
#   * 不使用 3080：端口与生产端口相同则直接拒绝运行；
#   * 只写 $SANDBOX（默认 /tmp/dsh-device-auth-sandbox）与 test/ 目录；
#   * 退出时 trap 杀掉沙箱进程，保留日志/证据供排查。
#
# 用法：
#   ./test/acceptance.sh                  # 默认沙箱与端口
#   SANDBOX=/tmp/mysbx PORT=3099 ./test/acceptance.sh
#   KEEP_SANDBOX=1 ./test/acceptance.sh   # 报告里提示保留（默认本就保留）
#
# 退出码：0 = 全部 PASS（或插件未就绪而 SKIP）；1 = 有 FAIL；2 = 前置条件错误
# =============================================================================
set -uo pipefail

# ── 路径与可调参数 ────────────────────────────────────────────────────────────

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PLUGIN_DIR=${PLUGIN_DIR:-$(cd -- "$SCRIPT_DIR/.." && pwd)}
PLUGIN_INDEX=${PLUGIN_INDEX:-$PLUGIN_DIR/lib/index.js}
PLUGIN_CLI=${PLUGIN_CLI:-$PLUGIN_DIR/bin/dsh-auth.mjs}

PROD_DSH_HOME=${PROD_DSH_HOME:-$HOME/.dsh}
PROD_PORT=${PROD_PORT:-3080}
SANDBOX=${SANDBOX:-/tmp/dsh-device-auth-sandbox}
HOME_DIR=$SANDBOX/home
PORT=${PORT:-3099}
BASE="http://127.0.0.1:$PORT"
STORE=$HOME_DIR/remote-auth.json
EVID=$SANDBOX/evidence

OVERLAY_BASE=$SANDBOX/overlay.yml
OVERLAY_PRINTURL=$SANDBOX/overlay-printurl-false.yml
LOG_BASE=$SANDBOX/dsh.log
LOG_RESTART=$SANDBOX/dsh-restart.log
LOG_PRINTURL=$SANDBOX/dsh-printurl-false.log

WAIT_READY_SECONDS=${WAIT_READY_SECONDS:-60}
COPY_STORAGES=${COPY_STORAGES:-1}
STORAGES_MAX_MB=${STORAGES_MAX_MB:-64}

ALL_IDS=(T1 T2 T3 T4 T5 T6 T7 T13 T14 T8 T9 T10 T11 T12)

DSH_BIN=${DSH_BIN:-$(command -v dsh 2>/dev/null || true)}
NODE_BIN=${NODE_BIN:-$(command -v node 2>/dev/null || true)}
CURL_BIN=${CURL_BIN:-$(command -v curl 2>/dev/null || true)}

# ── 状态 ─────────────────────────────────────────────────────────────────────
declare -A RES_STATUS=()
declare -A RES_DETAIL=()
declare -A RES_DONE=()
SANDBOX_PID=""
SANDBOX_LOG=""
ABORT_REASON=""
PROD_PID_BEFORE=""
PROD_PID_AFTER=""
PROD_GUARD_NOTE=""
DEVICE_TOKENS=()
CLI_RC=0
CLI_OUT=""
CLI_ERR=""

# ── 基础工具 ─────────────────────────────────────────────────────────────────

die() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }

info() { printf '\n=== %s ===\n' "$*"; }

note() { printf '  %s\n' "$*"; }

fatal() {
  ABORT_REASON=$1
  printf '\nFATAL: %s\n' "$1" >&2
  exit 1
}

port_in_use() {
  local port=$1
  if command -v ss >/dev/null 2>&1; then
    if ss -ltnH "sport = :$port" 2>/dev/null | grep -q .; then return 0; fi
  fi
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then return 0; fi
  return 1
}

port_listener_pid() {
  local port=$1
  command -v ss >/dev/null 2>&1 || return 0
  ss -ltnpH "sport = :$port" 2>/dev/null | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2
}

http_code() {
  local url=$1
  shift
  local code
  code=$("$CURL_BIN" -s -o /dev/null -w '%{http_code}' \
    --connect-timeout 3 --max-time 10 "$@" "$url" 2>/dev/null) || true
  printf '%s' "${code:-000}"
}

# fetch <tag> <cookie-jar> <url> [extra curl args...]
# 保存响应头到 $EVID/<tag>.hdr、响应体到 $EVID/<tag>.body，返回 HTTP 状态码。
fetch() {
  local tag=$1 jar=$2 url=$3
  shift 3
  local hdr="$EVID/$tag.hdr"
  local body="$EVID/$tag.body"
  [ -n "$jar" ] && [ ! -e "$jar" ] && : > "$jar"
  local code
  code=$("$CURL_BIN" -s -D "$hdr" -o "$body" -b "$jar" -c "$jar" \
    --connect-timeout 3 --max-time 10 -w '%{http_code}' "$@" "$url" 2>/dev/null) || true
  printf '%s' "${code:-000}"
}

hdr_get() {
  local file=$1 name=$2 line
  line=$(grep -i -m1 "^${name}:" "$file" 2>/dev/null || true)
  printf '%s' "${line#*:}" | sed 's/^[[:space:]]*//; s/\r$//'
}

# 从 CLI 输出（JSON 或文本）里取第一枚设备令牌。
extract_token() {
  grep -oE 'dsh_dev_[A-Za-z0-9_-]{43}' "$1" 2>/dev/null | head -1 || true
}

log_launch_token() {
  grep -oE 'token=[A-Za-z0-9_-]{20,}' "$1" 2>/dev/null | tail -1 | cut -d= -f2 || true
}

wait_launch_token() {
  local log=$1 i token
  for i in $(seq 1 30); do
    token=$(log_launch_token "$log")
    if [ -n "$token" ]; then printf '%s' "$token"; return 0; fi
    sleep 1
  done
  return 1
}

record() {
  local id=$1 status=$2
  shift 2
  RES_STATUS[$id]=$status
  RES_DETAIL[$id]=$*
  RES_DONE[$id]=1
  printf '  [%-4s] %-3s %s\n' "$status" "$id" "$*"
}

# ── CLI 封装（始终显式 --store/--origin，避免碰生产路径） ────────────────────

run_cli() {
  local tag=$1
  shift
  CLI_OUT=$EVID/cli-$tag.out
  CLI_ERR=$EVID/cli-$tag.err
  "$NODE_BIN" "$PLUGIN_CLI" "$@" --origin "$BASE" --store "$STORE" \
    >"$CLI_OUT" 2>"$CLI_ERR"
  CLI_RC=$?
}

cli_fail_detail() {
  local rc=$1 err=$2 first
  first=$(head -n 1 "$err" 2>/dev/null | cut -c1-300)
  printf 'rc=%s %s' "$rc" "${first:-<no stderr>}"
}

# ── 沙箱进程管理 ─────────────────────────────────────────────────────────────

# 注意：--patch 是 launcher 选项，必须排在任何 web app 选项（--port/--no-open）
# 之前，否则 web 参数解析器会报 "unknown option '--patch'"。
start_sandbox() {
  local overlay=$1 log=$2
  : > "$log"
  DSH_HOME="$HOME_DIR" "$DSH_BIN" --profile web --patch "$overlay" \
    --port "$PORT" --no-open >"$log" 2>&1 &
  SANDBOX_PID=$!
  SANDBOX_LOG=$log
}

wait_ready() {
  local log=$1 timeout=${2:-$WAIT_READY_SECONDS} i code
  for ((i = 1; i <= timeout; i++)); do
    if ! kill -0 "$SANDBOX_PID" 2>/dev/null; then
      return 2
    fi
    code=$(http_code "$BASE/connect?token=bogus")
    if [ "$code" = "401" ]; then return 0; fi
    sleep 1
  done
  return 1
}

boot_failure_detail() {
  local log=$1
  printf '%s' "$(tail -n 4 "$log" 2>/dev/null | tr '\n' ' ' | cut -c1-400)"
}

stop_sandbox() {
  local pid=${SANDBOX_PID:-}
  SANDBOX_PID=""
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
  fi
  local i
  for i in $(seq 1 40); do
    kill -0 "$pid" 2>/dev/null || break
    if ! port_in_use "$PORT"; then
      sleep 0.3
      kill -0 "$pid" 2>/dev/null || break
    fi
    sleep 0.25
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  for i in $(seq 1 20); do
    port_in_use "$PORT" || return 0
    sleep 0.25
  done
  return 1
}

# ── overlay 生成 ─────────────────────────────────────────────────────────────

write_overlay() {
  local file=$1 variant=${2:-base}
  {
    printf -- '- insert:\n'
    printf '    - id: device-auth\n'
    printf '      name: %s\n' "$PLUGIN_INDEX"
    printf '      config:\n'
    printf '        storePath: %s\n' "$STORE"
  } >"$file"
  if [ "$variant" = printurl-false ]; then
    # 与插件自身 bundle patch 相同的 web-runtime 覆盖：不打印启动 URL（R4）。
    cat >>"$file" <<'YAML'
- id: web-runtime
  name: '@deepseek-ai/dsh-web-app'
  config:
    openBrowser: !!js ctx.webStartup.openBrowser
    printUrl: false
    publicUrl: !!js ctx.webStartup.publicUrl
    surfaceContext: true
YAML
  fi
}

dump_config_check() {
  local overlay=$1 tag=$2
  DSH_HOME="$HOME_DIR" "$DSH_BIN" --profile web --patch "$overlay" \
    --dump-config >"$EVID/dump-$tag.yml" 2>"$EVID/dump-$tag.err"
  local rc=$?
  if [ $rc -ne 0 ]; then
    note "dump-config ($tag) rc=$rc: $(tail -n 2 "$EVID/dump-$tag.err" 2>/dev/null | tr '\n' ' ')"
    return 1
  fi
  if ! grep -q 'id: device-auth' "$EVID/dump-$tag.yml"; then
    note "dump-config ($tag) 里找不到 device-auth 行"
    return 1
  fi
  return 0
}

# ── 生产守卫 ─────────────────────────────────────────────────────────────────

prod_listener_pid() {
  local p
  p=$(port_listener_pid "$PROD_PORT")
  if [ -z "$p" ] && command -v systemctl >/dev/null 2>&1; then
    p=$(systemctl --user show -p MainPID --value dsh-web 2>/dev/null || true)
    [ "$p" = "0" ] && p=""
  fi
  printf '%s' "${p:-}"
}

# ── 汇总 ─────────────────────────────────────────────────────────────────────

print_summary() {
  local pass=0 fail=0 skip=0 id st dt line
  printf '\n================= ACCEPTANCE SUMMARY =================\n'
  printf '%-4s %-6s %s\n' ID STATUS DETAIL
  for id in "${ALL_IDS[@]}"; do
    if [ -n "${RES_DONE[$id]:-}" ]; then
      st=${RES_STATUS[$id]}
      dt=${RES_DETAIL[$id]}
    else
      st=FAIL
      dt="not executed${ABORT_REASON:+: $ABORT_REASON}"
    fi
    case "$st" in
      PASS) pass=$((pass + 1)) ;;
      FAIL) fail=$((fail + 1)) ;;
      SKIP) skip=$((skip + 1)) ;;
    esac
    printf '%-4s %-6s %s\n' "$id" "$st" "$dt"
  done
  printf -- '-----------------------------------------------------\n'
  printf 'PASS=%d FAIL=%d SKIP=%d\n' "$pass" "$fail" "$skip"

  printf '\nPRODUCTION GUARD (must not change): dsh-web :%s\n' "$PROD_PORT"
  if [ -n "$PROD_PID_BEFORE" ]; then
    if [ "$PROD_PID_BEFORE" = "$PROD_PID_AFTER" ]; then
      printf '  OK   pid before=%s after=%s (未重启)\n' "$PROD_PID_BEFORE" "$PROD_PID_AFTER"
    else
      printf '  FAIL pid before=%s after=%s (生产服务被改动！)\n' "$PROD_PID_BEFORE" "$PROD_PID_AFTER"
      fail=$((fail + 1))
    fi
  else
    printf '  SKIP 脚本启动时 :%s 不在监听，无法比对（不会去碰它）\n' "$PROD_PORT"
  fi
  [ -n "$PROD_GUARD_NOTE" ] && printf '  note %s\n' "$PROD_GUARD_NOTE"

  printf '\nSandbox 保留：%s\n  logs: *.log   store: %s   evidence: %s\n' \
    "${SANDBOX:-<unset>}" "${STORE:-<unset>}" "${EVID:-<unset>}"
  printf '  手动清理：rm -rf -- %s\n' "${SANDBOX:-<SANDBOX>}"

  if [ "$fail" -eq 0 ]; then
    printf '\nOVERALL: PASS\n'
    return 0
  fi
  printf '\nOVERALL: FAIL (%d failing)\n' "$fail"
  return 1
}

cleanup() {
  trap - EXIT INT TERM
  local stop_rc=0
  stop_sandbox || stop_rc=1
  PROD_PID_AFTER=$(prod_listener_pid)
  local rc=1
  if print_summary; then rc=0; fi
  if [ "$stop_rc" -ne 0 ]; then
    printf 'WARN: 沙箱端口 :%s 在退出时仍被占用（可能仍有沙箱进程）\n' "$PORT" >&2
    rc=1
  fi
  if [ -n "$PROD_PID_BEFORE" ] && [ "$PROD_PID_BEFORE" != "$PROD_PID_AFTER" ]; then
    rc=1
  fi
  exit "$rc"
}

# =============================================================================
# 1) 前置检查（不创建沙箱、不装 trap）
# =============================================================================

info "preflight"

if [ ! -f "$PLUGIN_INDEX" ] || [ ! -f "$PLUGIN_CLI" ]; then
  cat <<EOF
SKIP: 插件未就绪，未运行沙箱验收（exit 0）。

  期望的插件文件：
    - $PLUGIN_INDEX
    - $PLUGIN_CLI

  缺失：
$( [ -f "$PLUGIN_INDEX" ] || printf '    - %s\n' "$PLUGIN_INDEX"
   [ -f "$PLUGIN_CLI" ]   || printf '    - %s\n' "$PLUGIN_CLI" )

  插件就绪后重跑：$0
EOF
  exit 0
fi

[ -n "$DSH_BIN" ] || die "PATH 里找不到 dsh（可设置 DSH_BIN=/path/to/dsh）"
[ -n "$NODE_BIN" ] || die "PATH 里找不到 node（可设置 NODE_BIN=/path/to/node）"
[ -n "$CURL_BIN" ] || die "PATH 里找不到 curl"

[ -d "$PROD_DSH_HOME/profiles/web" ] || die "生产 DSH home 不存在：$PROD_DSH_HOME/profiles/web"
[ -f "$PROD_DSH_HOME/.credentials.yaml" ] || die "生产 DSH home 缺少 .credentials.yaml：$PROD_DSH_HOME"

[ "$PORT" != "$PROD_PORT" ] || die "PORT 不能等于生产端口 $PROD_PORT"
case "$PORT" in
  ''|*[!0-9]*) die "PORT 必须是数字：$PORT" ;;
esac

# 沙箱路径安全校验：必须在 /tmp 下，且不能与生产 home 重叠。
SANDBOX_REAL=$(readlink -m -- "$SANDBOX")
PROD_HOME_REAL=$(readlink -m -- "$PROD_DSH_HOME")
HOME_REAL=$(readlink -m -- "$HOME")
[ -n "$SANDBOX_REAL" ] && [ "$SANDBOX_REAL" != "/" ] && [ "$SANDBOX_REAL" != "/tmp" ] \
  || die "SANDBOX 路径不安全：$SANDBOX"
case "$SANDBOX_REAL" in
  /tmp/?*) ;;
  *)
    if [ "${ALLOW_NON_TMP_SANDBOX:-0}" != "1" ]; then
      die "SANDBOX 不在 /tmp 下（如确需，设置 ALLOW_NON_TMP_SANDBOX=1）：$SANDBOX_REAL"
    fi
    ;;
esac
[ "$SANDBOX_REAL" = "$PROD_HOME_REAL" ] && die "SANDBOX 不能是生产 DSH home"
case "$PROD_HOME_REAL/" in
  "$SANDBOX_REAL"/*) die "SANDBOX 不能包含生产 DSH home：$SANDBOX_REAL" ;;
esac
case "$SANDBOX_REAL/" in
  "$PROD_HOME_REAL"/*) die "SANDBOX 不能位于生产 DSH home 内：$SANDBOX_REAL" ;;
esac
[ "$SANDBOX_REAL" = "$HOME_REAL" ] && die "SANDBOX 不能是 \$HOME"

if port_in_use "$PORT"; then
  die "端口 :$PORT 已被占用（pid=$(port_listener_pid "$PORT")）。本脚本不会去杀未知进程；请换 PORT 或先自行清理。"
fi

PROD_PID_BEFORE=$(prod_listener_pid)
note "dsh        = $DSH_BIN"
note "node       = $NODE_BIN"
note "plugin     = $PLUGIN_INDEX"
note "sandbox    = $SANDBOX_REAL  (port :$PORT)"
note "production = $PROD_HOME_REAL (:${PROD_PORT} pid=${PROD_PID_BEFORE:-none}) — 只读复制，绝不重启"

# =============================================================================
# 2) 准备沙箱（此处开始失败要清理）
# =============================================================================

trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup EXIT

info "prepare sandbox"

rm -rf -- "$SANDBOX_REAL"
mkdir -p -- "$HOME_DIR" "$EVID"
chmod 700 "$SANDBOX_REAL" "$HOME_DIR"
cp -a -- "$PROD_HOME_REAL/profiles" "$HOME_DIR/" || fatal "复制 profiles 失败"
cp -a -- "$PROD_HOME_REAL/.credentials.yaml" "$HOME_DIR/" || fatal "复制 .credentials.yaml 失败"
chmod 700 "$HOME_DIR"
chmod 600 "$HOME_DIR/.credentials.yaml" 2>/dev/null || true

if [ "$COPY_STORAGES" = "1" ] && [ -d "$PROD_HOME_REAL/storages" ]; then
  storages_mb=$(du -sm -- "$PROD_HOME_REAL/storages" 2>/dev/null | cut -f1)
  storages_mb=${storages_mb:-0}
  if [ "$storages_mb" -le "$STORAGES_MAX_MB" ]; then
    cp -a -- "$PROD_HOME_REAL/storages" "$HOME_DIR/" 2>/dev/null || true
    note "storages 已复制（${storages_mb}MB ≤ ${STORAGES_MAX_MB}MB）"
  else
    note "storages 跳过（${storages_mb}MB > ${STORAGES_MAX_MB}MB；最小 home 已验证可启动）"
  fi
else
  note "storages 跳过（COPY_STORAGES=$COPY_STORAGES）"
fi
chmod 700 "$HOME_DIR"
# 沙箱绝不带 sessions/attachments/cache —— 只复制上面明确列出的内容。

write_overlay "$OVERLAY_BASE" base
write_overlay "$OVERLAY_PRINTURL" printurl-false

if ! dump_config_check "$OVERLAY_BASE" base; then
  fatal "overlay 合成失败（--dump-config 未解析出 device-auth 行）"
fi
if ! dump_config_check "$OVERLAY_PRINTURL" printurl-false; then
  fatal "printUrl:false 变体 overlay 合成失败"
fi
if ! grep -q 'printUrl: false' "$EVID/dump-printurl-false.yml"; then
  fatal "printUrl:false 变体 overlay 未生效（dump 里没有 printUrl: false）"
fi
note "overlay 合成 OK（base 与 printUrl:false 变体）"

# =============================================================================
# 3) 基线沙箱：T1–T7、T11
# =============================================================================

info "boot sandbox (base overlay)"
start_sandbox "$OVERLAY_BASE" "$LOG_BASE"
if ! wait_ready "$LOG_BASE" "$WAIT_READY_SECONDS"; then
  detail=$(boot_failure_detail "$LOG_BASE")
  record T1 FAIL "sandbox 启动失败：$detail"
  fatal "sandbox ($BASE) 启动失败：$detail"
fi
note "ready in ≤${WAIT_READY_SECONDS}s: $BASE  (pid=$SANDBOX_PID)"

# ---- T1 未授权 -------------------------------------------------------------
info "T1 unauthorized token"
code=$(http_code "$BASE/connect?token=bogus")
if [ "$code" = "401" ]; then
  record T1 PASS "bogus -> 401"
else
  record T1 FAIL "bogus -> $code (expected 401)"
fi

# ---- T2 设备令牌换取凭据 ----------------------------------------------------
info "T2 device token via CLI add"
run_cli t2-add add phone --json
if [ "$CLI_RC" -ne 0 ]; then
  record T2 FAIL "dsh-auth add 失败：$(cli_fail_detail "$CLI_RC" "$CLI_ERR")"
  fatal "dsh-auth add 失败，后续用例无法继续"
fi
TOK1=$(extract_token "$CLI_OUT")
if [ -z "$TOK1" ]; then
  record T2 FAIL "add 输出里没有 dsh_dev_ 令牌：$(head -c 200 "$CLI_OUT" | tr '\n' ' ')"
  fatal "CLI 未打印设备令牌"
fi
DEVICE_TOKENS+=("$TOK1")
JAR_T2=$EVID/jar-t2.txt
: >"$JAR_T2"
code=$(fetch t2-connect "$JAR_T2" "$BASE/connect?token=$TOK1")
set_cookie=$(hdr_get "$EVID/t2-connect.hdr" set-cookie)
location=$(hdr_get "$EVID/t2-connect.hdr" location)
if [ "$code" = "302" ] && [ -n "$set_cookie" ]; then
  record T2 PASS "/connect 302, Set-Cookie 有, location=${location:-?}, token=${TOK1:0:12}…"
else
  record T2 FAIL "/connect -> $code, Set-Cookie='${set_cookie:0:40}', location=${location:-none}"
fi

# ---- T3 /connect cookie 的可用性（v2/operator cookie，仅用于 /api） ---------
# 说明：/connect 铸造的是 v2 operator cookie，只对 /api 有效；用它 GET / 返回
# 401 是设计行为。浏览器页面用的 v1 cookie 由 T4 的 /?token= 流程验证。
info "T3 cookie usable (/api, v2 operator cookie)"
code_api=$(fetch t3-api "$JAR_T2" "$BASE/api/")
code_root=$(fetch t3-root "$JAR_T2" "$BASE/")
if [ "$code_api" = "404" ]; then
  record T3 PASS "/api/ with /connect cookie -> 404（已过鉴权；GET / -> $code_root 为设计内 401）"
else
  record T3 FAIL "/api/ with /connect cookie -> $code_api (expected 404=authenticated; GET / -> $code_root)"
fi

# ---- T4 浏览器 index 流（v1 cookie） ---------------------------------------
info "T4 browser index flow /?token="
JAR_T4=$EVID/jar-t4.txt
: >"$JAR_T4"
code=$(fetch t4-index "$JAR_T4" "$BASE/?token=$TOK1")
set_cookie4=$(hdr_get "$EVID/t4-index.hdr" set-cookie)
location4=$(hdr_get "$EVID/t4-index.hdr" location)
code_page=$(fetch t4-page "$JAR_T4" "$BASE/")
ctype=$(hdr_get "$EVID/t4-page.hdr" content-type)
if [ "$code" = "303" ] && [ -n "$set_cookie4" ] && [ "$code_page" = "200" ] \
  && [ "${ctype#text/html}" != "$ctype" ]; then
  record T4 PASS "/?token= 303 + Set-Cookie(${location4:-?}), cookie GET / 200 ${ctype}"
else
  record T4 FAIL "/?token= -> $code, Set-Cookie='${set_cookie4:0:30}', cookie GET / -> $code_page ${ctype}"
fi

# ---- T5 真实 launch token 零回归 -------------------------------------------
info "T5 real launch token (no regression)"
if LAUNCH_TOKEN=$(wait_launch_token "$LOG_BASE"); then
  JAR_T5=$EVID/jar-t5.txt
  : >"$JAR_T5"
  code=$(fetch t5-connect "$JAR_T5" "$BASE/connect?token=$LAUNCH_TOKEN")
  set_cookie5=$(hdr_get "$EVID/t5-connect.hdr" set-cookie)
  if [ "$code" = "302" ] && [ -n "$set_cookie5" ]; then
    record T5 PASS "launch token ${LAUNCH_TOKEN:0:10}… -> /connect 302 + Set-Cookie"
  else
    record T5 FAIL "launch token -> $code (expected 302), Set-Cookie='${set_cookie5:0:30}'"
  fi
else
  record T5 SKIP "日志里没有 'token=' 启动 URL（printUrl 可能被关闭）；无法测 launch token 零回归"
fi

# ---- T11 Host fence 不回归 -------------------------------------------------
info "T11 Host fence"
code=$(http_code "$BASE/connect?token=$TOK1" -H 'Host: evil.example')
if [ "$code" = "403" ]; then
  record T11 PASS "Host: evil.example + valid device token -> 403"
else
  record T11 FAIL "Host: evil.example -> $code (expected 403)"
fi

# ---- T6 轮换 ---------------------------------------------------------------
info "T6 rotate"
run_cli t6-rotate rotate phone --json
if [ "$CLI_RC" -ne 0 ]; then
  record T6 FAIL "dsh-auth rotate 失败：$(cli_fail_detail "$CLI_RC" "$CLI_ERR")"
else
  TOK2=$(extract_token "$CLI_OUT")
  if [ -z "$TOK2" ]; then
    record T6 FAIL "rotate 输出里没有设备令牌"
  else
    DEVICE_TOKENS+=("$TOK2")
    JAR_OLD=$EVID/jar-old.txt
    JAR_NEW=$EVID/jar-new.txt
    : >"$JAR_OLD"
    : >"$JAR_NEW"
    code_old=$(fetch t6-old "$JAR_OLD" "$BASE/connect?token=$TOK1")
    code_new=$(fetch t6-new "$JAR_NEW" "$BASE/connect?token=$TOK2")
    set_cookie_new=$(hdr_get "$EVID/t6-new.hdr" set-cookie)
    if [ "$code_old" = "401" ] && [ "$code_new" = "302" ] && [ -n "$set_cookie_new" ]; then
      record T6 PASS "old -> 401, new -> 302 + cookie (new=${TOK2:0:12}…)"
    else
      record T6 FAIL "old -> $code_old (exp 401), new -> $code_new (exp 302)"
    fi
  fi
fi

# ---- T7 撤销 ---------------------------------------------------------------
info "T7 revoke"
run_cli t7-revoke revoke phone --json
if [ "$CLI_RC" -ne 0 ]; then
  record T7 FAIL "dsh-auth revoke 失败：$(cli_fail_detail "$CLI_RC" "$CLI_ERR")"
else
  JAR_REV=$EVID/jar-rev.txt
  : >"$JAR_REV"
  code_rev=$(fetch t7-revoked "$JAR_REV" "$BASE/connect?token=$TOK2")
  run_cli t7-list list --json
  if [ "$CLI_RC" -ne 0 ]; then
    record T7 FAIL "令牌 -> $code_rev；但 dsh-auth list 失败：$(cli_fail_detail "$CLI_RC" "$CLI_ERR")"
  else
    list_check=$("$NODE_BIN" -e '
const fs = require("node:fs");
const data = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
const device = (data.devices || []).find((item) => item.label === "phone");
if (!device) { console.log("phone 不在 list 里"); process.exit(0); }
const revoked = typeof device.revokedAt === "string" && device.revokedAt !== "";
console.log(`status=${device.status} revokedAt=${device.revokedAt} ${revoked ? "REVOKED" : "NOT-REVOKED"}`);
' "$CLI_OUT" 2>&1) || true
    if [ "$code_rev" = "401" ] && printf '%s' "$list_check" | grep -q 'status=revoked'; then
      record T7 PASS "revoked token -> 401; list: $list_check"
    else
      record T7 FAIL "token -> $code_rev (exp 401); list: $list_check"
    fi
  fi
fi

# ---- T13 撤销即时生效：已签发的 /api cookie 下一次请求即 401 ------------
info "T13 revoked device API cookie is rejected on the next request"
code_api_rev=$(fetch t13-api "$JAR_T2" "$BASE/api/")
if [ "$code_api_rev" = "401" ]; then
  record T13 PASS "revoked phone: 已签发的 /connect cookie 再请求 /api/ -> 401（撤销前为 404）"
else
  record T13 FAIL "revoked phone: /api/ with already-minted cookie -> $code_api_rev (expected 401)"
fi

# ---- T14 撤销即时生效：浏览器 v1 cookie 下一次请求即 401 -------------------
info "T14 revoked device browser cookie is rejected on the next request"
code_page_rev=$(fetch t14-page "$JAR_T4" "$BASE/")
if [ "$code_page_rev" = "401" ]; then
  record T14 PASS "revoked phone: 已签发的浏览器 cookie GET / -> 401（撤销前为 200）"
else
  record T14 FAIL "revoked phone: GET / with already-minted browser cookie -> $code_page_rev (expected 401)"
fi

# =============================================================================
# 4) T8 重启保持（R1）
# =============================================================================

info "T8 restart persistence"
run_cli t8-add add tablet --json
if [ "$CLI_RC" -ne 0 ]; then
  record T8 FAIL "dsh-auth add tablet 失败：$(cli_fail_detail "$CLI_RC" "$CLI_ERR")"
else
  TOK3=$(extract_token "$CLI_OUT")
  if [ -z "$TOK3" ]; then
    record T8 FAIL "add tablet 输出里没有设备令牌"
  else
    DEVICE_TOKENS+=("$TOK3")
    OLD_LAUNCH=$(log_launch_token "$LOG_BASE")
    if ! stop_sandbox; then
      record T8 FAIL "无法停止第一个沙箱进程（端口 :$PORT 未释放）"
      fatal "沙箱停止失败"
    fi
    start_sandbox "$OVERLAY_BASE" "$LOG_RESTART"
    if ! wait_ready "$LOG_RESTART" "$WAIT_READY_SECONDS"; then
      detail=$(boot_failure_detail "$LOG_RESTART")
      record T8 FAIL "重启失败：$detail"
      fatal "sandbox 重启失败：$detail"
    fi
    NEW_LAUNCH=$(log_launch_token "$LOG_RESTART")
    JAR_T8=$EVID/jar-t8.txt
    : >"$JAR_T8"
    code=$(fetch t8-tablet "$JAR_T8" "$BASE/connect?token=$TOK3")
    set_cookie8=$(hdr_get "$EVID/t8-tablet.hdr" set-cookie)
    if [ "$code" = "302" ] && [ -n "$set_cookie8" ]; then
      record T8 PASS "restart 后 tablet token 仍 302 + cookie（launch ${OLD_LAUNCH:0:8}… -> ${NEW_LAUNCH:0:8}…）"
    else
      record T8 FAIL "restart 后 tablet -> $code (exp 302), Set-Cookie='${set_cookie8:0:30}'"
    fi
  fi
fi

# =============================================================================
# 5) T12 printUrl:false 变体
# =============================================================================

info "T12 printUrl:false variant"
if [ -z "${TOK3:-}" ]; then
  record T12 FAIL "缺少可用设备令牌（T8 未成功），无法验证变体"
else
  if ! stop_sandbox; then
    record T12 FAIL "无法停止沙箱进程（端口 :$PORT 未释放）"
    fatal "沙箱停止失败"
  fi
  start_sandbox "$OVERLAY_PRINTURL" "$LOG_PRINTURL"
  if ! wait_ready "$LOG_PRINTURL" "$WAIT_READY_SECONDS"; then
    detail=$(boot_failure_detail "$LOG_PRINTURL")
    record T12 FAIL "printUrl:false 变体启动失败：$detail"
    fatal "printUrl:false 变体启动失败：$detail"
  fi
  url_lines=$(grep -c 'dsh web: http' "$LOG_PRINTURL" 2>/dev/null || true)
  leaked=$(grep -oE 'token=[A-Za-z0-9_-]{20,}' "$LOG_PRINTURL" 2>/dev/null | head -1 || true)
  JAR_T12=$EVID/jar-t12.txt
  : >"$JAR_T12"
  code=$(fetch t12-tablet "$JAR_T12" "$BASE/connect?token=$TOK3")
  set_cookie12=$(hdr_get "$EVID/t12-tablet.hdr" set-cookie)
  if [ "${url_lines:-0}" -eq 0 ] && [ -z "$leaked" ] && [ "$code" = "302" ] && [ -n "$set_cookie12" ]; then
    record T12 PASS "日志无启动 URL/token=；device token 仍 302 + cookie"
  else
    record T12 FAIL "url_lines=${url_lines:-?}, leaked='${leaked}', token -> $code (exp 302)"
  fi
fi

# =============================================================================
# 6) T9 日志/存储无明文 + T10 文件权限（在最终 store 与全部日志上检查）
# =============================================================================

info "T9 no plaintext in logs/store"
if [ ! -f "$STORE" ]; then
  record T9 FAIL "store 不存在：$STORE（CLI 未成功写入）"
else
  # 9a. store：结构合法、只有 tokenHash、无明文令牌
  store_check=$("$NODE_BIN" -e '
const fs = require("node:fs");
const path = process.argv[1];
let parsed;
try { parsed = JSON.parse(fs.readFileSync(path, "utf8")); }
catch (error) { console.log(`FAIL: unreadable JSON: ${error.message}`); process.exit(0); }
const problems = [];
if (parsed.version !== 1) problems.push("version!=1");
if (!Array.isArray(parsed.devices)) problems.push("devices 不是数组");
const allowed = new Set(["id", "label", "tokenHash", "createdAt", "expiresAt", "revokedAt", "clientKind"]);
for (const device of parsed.devices || []) {
  for (const key of Object.keys(device)) {
    if (!allowed.has(key)) problems.push(`意外字段 ${key}`);
  }
  if (!/^[0-9a-f]{64}$/.test(String(device.tokenHash))) problems.push("tokenHash 不是 sha256 hex");
}
const text = fs.readFileSync(path, "utf8");
if (/dsh_dev_[A-Za-z0-9_-]{43}/.test(text)) problems.push("store 含明文设备令牌");
console.log(problems.length ? `FAIL: ${problems.join("; ")}` : "OK");
' "$STORE" 2>&1) || true

  # 9b. 日志：既不能出现已知设备令牌，也不能出现任意 dsh_dev_ 令牌
  log_hits=""
  shopt -s nullglob
  for logfile in "$SANDBOX"/*.log; do
    for token in "${DEVICE_TOKENS[@]}"; do
      if grep -qF -- "$token" "$logfile" 2>/dev/null; then
        log_hits="$log_hits $(basename "$logfile"):known-token"
      fi
    done
    if grep -qE 'dsh_dev_[A-Za-z0-9_-]{43}' "$logfile" 2>/dev/null; then
      log_hits="$log_hits $(basename "$logfile"):dsh_dev-pattern"
    fi
  done
  shopt -u nullglob

  if [ "$store_check" = "OK" ] && [ -z "$log_hits" ]; then
    record T9 PASS "store 仅 tokenHash；日志无明文（$(basename "$LOG_BASE"), $(basename "$LOG_RESTART"), $(basename "$LOG_PRINTURL")）"
  else
    record T9 FAIL "store=${store_check}; logs=${log_hits:-none}"
  fi
fi

info "T10 file permissions"
if [ ! -f "$STORE" ]; then
  record T10 FAIL "store 不存在：$STORE"
else
  store_mode=$(stat -c '%a' "$STORE" 2>/dev/null || echo '?')
  dir_mode=$(stat -c '%a' "$(dirname "$STORE")" 2>/dev/null || echo '?')
  if [ "$store_mode" = "600" ] && [ "$dir_mode" = "700" ]; then
    record T10 PASS "store=$store_mode dir=$dir_mode"
  else
    record T10 FAIL "store=$store_mode (exp 600) dir=$dir_mode (exp 700)"
  fi
fi

# =============================================================================
# 收尾：cleanup (trap) 停止沙箱、检查生产 PID、打印汇总
# =============================================================================
info "done — stopping sandbox"
exit 0
