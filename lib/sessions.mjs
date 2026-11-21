/**
 * Session index for the durable device credentials.
 *
 * A device token is exchanged by the real `client-connection` implementation,
 * which mints an ordinary signed cookie. That cookie carries no device
 * identity, so revoking the device could not evict a session it already holds.
 *
 * This module closes that gap without touching the cookie format or the signing
 * secret: when an exchange happens for a device token, the plugin records
 * `sha256(<cookie-name>=<cookie-value>)` with the device id. On every later
 * request the plugin hashes the presented cookies and rejects a request whose
 * cookie belongs to a revoked or expired device. Only hashes are stored.
 *
 * The map is an append-only index keyed by cookie hash:
 * - a revoked device is rejected on its next request;
 * - cookies minted with the real launch token (or before this plugin existed)
 *   have no entry and are delegated to the original authentication unchanged;
 * - a deleted cookie entry cannot help an attacker: without a cookie the
 *   original authentication rejects the request anyway.
 */
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'

export const SESSIONS_VERSION = 1
export const SESSIONS_FILE_NAME = 'remote-auth-sessions.json'
const MAX_SESSIONS = 4096
const HASH_PATTERN = /^[0-9a-f]{64}$/
const PRUNE_MARGIN_MS = 60_000

/** The session index lives beside the credential store. */
export function resolveSessionsPath(storePath, explicit) {
  if (typeof explicit === 'string' && explicit.trim() !== '') return explicit.trim()
  return join(dirname(storePath), SESSIONS_FILE_NAME)
}

/** SHA-256 hex digest of one `name=value` cookie pair. */
export function hashCookiePair(pair) {
  return createHash('sha256').update(pair, 'utf8').digest('hex')
}

/** Normalize one `name=value` pair (trim, drop surrounding whitespace only). */
export function normalizeCookiePair(pair) {
  if (typeof pair !== 'string') return undefined
  const trimmed = pair.trim()
  const at = trimmed.indexOf('=')
  if (at <= 0) return undefined
  return `${trimmed.slice(0, at).trim()}=${trimmed.slice(at + 1).trim()}`
}

/**
 * Turn one `Set-Cookie` header value into a `name=value` pair plus its expiry.
 * @returns {{ pair: string, expiresAt: string | null } | undefined}
 */
export function sessionFromSetCookie(setCookie, now = Date.now()) {
  if (typeof setCookie !== 'string') return undefined
  const segments = setCookie.split(';')
  const pair = normalizeCookiePair(segments[0])
  if (pair === undefined) return undefined
  let expiresAt = null
  for (const segment of segments.slice(1)) {
    const at = segment.indexOf('=')
    if (at === -1) continue
    const name = segment.slice(0, at).trim().toLowerCase()
    const value = segment.slice(at + 1).trim()
    if (name === 'max-age') {
      const seconds = Number(value)
      if (Number.isFinite(seconds) && seconds > 0) expiresAt = new Date(now + seconds * 1000).toISOString()
    } else if (name === 'expires' && expiresAt === null) {
      const time = Date.parse(value)
      if (Number.isFinite(time)) expiresAt = new Date(time).toISOString()
    }
  }
  return { pair, expiresAt }
}

/** Read a Cookie request header (string) into normalized `name=value` pairs. */
export function cookiePairsFromHeader(headerValue) {
  if (typeof headerValue !== 'string' || headerValue.trim() === '') return []
  const pairs = []
  for (const segment of headerValue.split(';')) {
    const pair = normalizeCookiePair(segment)
    if (pair !== undefined) pairs.push(pair)
  }
  return pairs
}

/** Read the Cookie header from a Node request or a Fetch `Request`. */
export function cookieHeaderOf(request) {
  const headers = request?.headers
  if (headers === undefined || headers === null) return undefined
  if (typeof headers.get === 'function') {
    const value = headers.get('cookie')
    return value === null || value === undefined ? undefined : String(value)
  }
  const value = headers.cookie ?? headers.Cookie
  return typeof value === 'string' ? value : undefined
}

const isoOrNull = (value) => {
  if (typeof value !== 'string') return null
  const time = Date.parse(value)
  return Number.isFinite(time) ? new Date(time).toISOString() : null
}

/** Empty session index. */
export function emptySessions() {
  return { version: SESSIONS_VERSION, sessions: [] }
}

/** Normalize decoded JSON into the session index; malformed entries are dropped. */
export function normalizeSessions(raw) {
  if (raw === null || typeof raw !== 'object' || !Array.isArray(raw.sessions)) return emptySessions()
  const sessions = []
  const seen = new Set()
  for (const entry of raw.sessions) {
    if (entry === null || typeof entry !== 'object') continue
    const cookieHash = typeof entry.cookieHash === 'string' && HASH_PATTERN.test(entry.cookieHash)
      ? entry.cookieHash
      : undefined
    const deviceId = typeof entry.deviceId === 'string' && entry.deviceId !== '' ? entry.deviceId : undefined
    const key = cookieHash === undefined || deviceId === undefined ? undefined : `${cookieHash}:${deviceId}`
    if (key === undefined || seen.has(key)) continue
    seen.add(key)
    sessions.push({
      cookieHash,
      deviceId,
      issuedAt: isoOrNull(entry.issuedAt) ?? new Date().toISOString(),
      expiresAt: isoOrNull(entry.expiresAt),
    })
  }
  return { version: SESSIONS_VERSION, sessions }
}

/**
 * Read the session index synchronously (the Host authentication path is sync).
 * A missing file is an empty index, never an error.
 */
export function readSessionsFile(path) {
  let stat
  try {
    stat = statSync(path)
  } catch (error) {
    if (error?.code === 'ENOENT') return { sessions: [], exists: false, mtimeMs: -1, size: -1 }
    throw error
  }
  const raw = JSON.parse(readFileSync(path, 'utf8'))
  const store = normalizeSessions(raw)
  return { sessions: store.sessions, exists: true, mtimeMs: stat.mtimeMs, size: stat.size }
}

/** Atomically replace the session index (0700 directory, 0600 file). */
export function writeSessionsFile(path, sessions) {
  const directory = dirname(path)
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  try { chmodSync(directory, 0o700) } catch { /* best effort */ }
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  writeFileSync(temporary, `${JSON.stringify({ version: SESSIONS_VERSION, sessions }, null, 2)}\n`, { mode: 0o600 })
  try { chmodSync(temporary, 0o600) } catch { /* best effort */ }
  renameSync(temporary, path)
  try { chmodSync(path, 0o600) } catch { /* best effort */ }
}

/** Drop expired entries, keeping at most `MAX_SESSIONS` newest records. */
export function pruneSessions(sessions, now = Date.now()) {
  const kept = sessions.filter((session) => {
    if (typeof session.expiresAt !== 'string') return true
    const expires = Date.parse(session.expiresAt)
    return !Number.isFinite(expires) || expires + PRUNE_MARGIN_MS > now
  })
  if (kept.length <= MAX_SESSIONS) return kept
  return kept.slice(kept.length - MAX_SESSIONS)
}

/**
 * Add or refresh one mapped session and drop expired records.
 * @returns {boolean} whether the index changed
 */
export function mergeSession(sessions, entry, now = Date.now()) {
  const pruned = pruneSessions(sessions, now)
  const index = pruned.findIndex((session) => session.cookieHash === entry.cookieHash && session.deviceId === entry.deviceId)
  if (index !== -1) pruned.splice(index, 1)
  pruned.push(entry)
  const final = pruneSessions(pruned, now)
  const same = final.length === sessions.length
    && final.every((session, at) => session.cookieHash === sessions[at]?.cookieHash
      && session.deviceId === sessions[at]?.deviceId
      && session.expiresAt === sessions[at]?.expiresAt)
  if (same) return false
  sessions.splice(0, sessions.length, ...final)
  return true
}

/** Remove every session mapped to one device; returns how many were removed. */
export function removeSessionsForDevice(sessions, deviceId) {
  const before = sessions.length
  const kept = sessions.filter((session) => session.deviceId !== deviceId)
  sessions.splice(0, sessions.length, ...kept)
  return before - kept.length
}
