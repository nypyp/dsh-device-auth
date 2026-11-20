/**
 * Device credential store shared by the Host plugin and the `dsh-auth` CLI.
 *
 * Credential model (borrowed from OpenChamber's `remote-clients` store):
 * - One durable, per-device login token; the plaintext leaves this module only
 *   once, from the mint/rotate call that created it.
 * - Only the SHA-256 hex digest is persisted. Tokens are compared in constant
 *   time over decoded hex buffers of equal length.
 * - The store file is written atomically (temp file + rename) with mode 0600
 *   inside a 0700 directory.
 * - Cross-process mutation is serialized with a `.lock` directory so the CLI
 *   and any future writer cannot drop each other's device records.
 *
 * The Host plugin itself never writes the store; it only reads it, so a CLI
 * mutation can never be resurrected by a stale in-process snapshot.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import {
  chmodSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'

export const STORE_VERSION = 1
/** Prefix every device credential carries; the plugin uses it to skip the store read for ordinary launch tokens. */
export const TOKEN_PREFIX = 'dsh_dev_'
export const DEFAULT_LABEL = 'device'
export const MAX_LABEL_LENGTH = 80
const TOKEN_BYTES = 32
const HASH_PATTERN = /^[0-9a-f]{64}$/
const LOCK_RETRY_MS = 50
const LOCK_TIMEOUT_MS = 3000
const LOCK_STALE_MS = 30_000

/** Resolve the store path: explicit value, else `$DSH_HOME/remote-auth.json`, else `~/.dsh/remote-auth.json`. */
export function resolveStorePath(explicit) {
  if (typeof explicit === 'string' && explicit.trim() !== '') return resolve(explicit.trim())
  const home = process.env.DSH_HOME?.trim() !== '' ? process.env.DSH_HOME : join(homedir(), '.dsh')
  return join(home, 'remote-auth.json')
}

/** SHA-256 hex digest of a presented token. */
export function hashToken(token) {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

/** Mint one device token: a stable prefix plus 32 random bytes in base64url (43 chars). */
export function generateToken(prefix = TOKEN_PREFIX) {
  return `${prefix}${randomBytes(TOKEN_BYTES).toString('base64url')}`
}

/** Normalize a human label to a non-empty, length-capped display name. */
export function normalizeLabel(value) {
  const text = typeof value === 'string' ? value.trim() : ''
  return (text === '' ? DEFAULT_LABEL : text).slice(0, MAX_LABEL_LENGTH)
}

/** Case-insensitive identity of a label; a re-pair of the same device rotates its token. */
export function labelKey(value) {
  return normalizeLabel(value).toLowerCase()
}

/** Fresh device id. */
export function generateDeviceId() {
  return `dev_${randomBytes(12).toString('hex')}`
}

const isoOrNull = (value) => {
  if (typeof value !== 'string') return null
  const time = Date.parse(value)
  return Number.isFinite(time) ? new Date(time).toISOString() : null
}

/** Empty store document. */
export function emptyStore() {
  return { version: STORE_VERSION, devices: [] }
}

/**
 * Normalize any decoded JSON into a store. Malformed records are dropped rather
 * than repaired: a record without a usable hash must not authenticate anything.
 */
export function normalizeStore(raw) {
  if (raw === null || typeof raw !== 'object' || !Array.isArray(raw.devices)) return emptyStore()
  const devices = []
  for (const entry of raw.devices) {
    if (entry === null || typeof entry !== 'object') continue
    const id = typeof entry.id === 'string' && entry.id !== '' ? entry.id : undefined
    const tokenHash = typeof entry.tokenHash === 'string' && HASH_PATTERN.test(entry.tokenHash)
      ? entry.tokenHash
      : undefined
    if (id === undefined || tokenHash === undefined) continue
    devices.push({
      id,
      label: normalizeLabel(entry.label),
      tokenHash,
      createdAt: isoOrNull(entry.createdAt) ?? new Date().toISOString(),
      expiresAt: isoOrNull(entry.expiresAt),
      revokedAt: isoOrNull(entry.revokedAt),
      clientKind: typeof entry.clientKind === 'string' && entry.clientKind !== '' ? entry.clientKind : null,
    })
  }
  return { version: STORE_VERSION, devices }
}

/**
 * Read the store synchronously (the Host auth path is synchronous).
 * @param {string} path
 * @returns {{ store: object, exists: boolean, mtimeMs: number, size: number }}
 */
export function readStoreFile(path) {
  let stat
  try {
    stat = statSync(path)
  } catch (error) {
    if (error?.code === 'ENOENT') return { store: emptyStore(), exists: false, mtimeMs: -1, size: -1 }
    throw error
  }
  const text = readFileSync(path, 'utf8')
  let raw
  try {
    raw = JSON.parse(text)
  } catch (error) {
    const wrapped = new Error(`device-auth: ${path} is not valid JSON`)
    wrapped.cause = error
    throw wrapped
  }
  return { store: normalizeStore(raw), exists: true, mtimeMs: stat.mtimeMs, size: stat.size }
}

/** Atomically replace the store: 0700 directory, 0600 file, temp file + rename. */
export function writeStoreFile(path, store) {
  const directory = dirname(path)
  mkdirSync(directory, { recursive: true, mode: 0o700 })
  try { chmodSync(directory, 0o700) } catch { /* best effort on filesystems without modes */ }
  const temporary = `${path}.${process.pid}.${Date.now()}.tmp`
  writeFileSync(temporary, `${JSON.stringify(store, null, 2)}\n`, { mode: 0o600 })
  try { chmodSync(temporary, 0o600) } catch { /* best effort */ }
  renameSync(temporary, path)
  try { chmodSync(path, 0o600) } catch { /* best effort */ }
}

const sleep = (ms) => new Promise((done) => { setTimeout(done, ms) })

/**
 * Serialize a cross-process read-modify-write of the store.
 * @param {string} path - store path; the lock is `<path>.lock`.
 * @param {() => Promise<T>} mutate - runs while the lock is held.
 * @returns {Promise<T>}
 */
export async function withStoreLock(path, mutate) {
  const lock = `${path}.lock`
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const deadline = Date.now() + LOCK_TIMEOUT_MS
  for (;;) {
    try {
      mkdirSync(lock)
      break
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error
      let stale = false
      try {
        stale = Date.now() - statSync(lock).mtimeMs > LOCK_STALE_MS
      } catch {
        continue
      }
      if (stale) {
        rmSync(lock, { recursive: true, force: true })
        continue
      }
      if (Date.now() > deadline) throw new Error(`device-auth: timed out waiting for ${lock}; remove it if no other dsh-auth is running`)
      await sleep(LOCK_RETRY_MS)
    }
  }
  try {
    return await mutate()
  } finally {
    rmSync(lock, { recursive: true, force: true })
  }
}

/** True when the record is neither revoked nor expired at `now`. */
export function isActiveDevice(device, now = Date.now()) {
  if (device.revokedAt !== null && device.revokedAt !== undefined) return false
  if (typeof device.expiresAt === 'string' && device.expiresAt !== '') {
    const expires = Date.parse(device.expiresAt)
    if (Number.isFinite(expires) && expires <= now) return false
  }
  return true
}

/**
 * Find the active device whose stored hash matches `token`, comparing in
 * constant time. Returns undefined for any token that is not a device token.
 */
export function findActiveDevice(store, token, now = Date.now()) {
  if (typeof token !== 'string' || !token.startsWith(TOKEN_PREFIX)) return undefined
  const candidate = Buffer.from(hashToken(token), 'hex')
  for (const device of store.devices) {
    if (!isActiveDevice(device, now)) continue
    const stored = Buffer.from(device.tokenHash, 'hex')
    if (stored.length !== candidate.length) continue
    if (timingSafeEqual(stored, candidate)) return device
  }
  return undefined
}

/** Resolve a device by exact id or by case-insensitive label. */
export function findDevice(store, key) {
  const text = typeof key === 'string' ? key.trim() : ''
  if (text === '') return undefined
  const exact = store.devices.find((device) => device.id === text)
  if (exact !== undefined) return exact
  const wanted = text.toLowerCase()
  return store.devices.find((device) => device.label.toLowerCase() === wanted)
}

/**
 * Mint a token for `label`. Minting an already known label rotates that device
 * in place: its id and creation time survive, old tokens stop matching, and
 * the display label is not reset by the re-pair.
 * @returns {{ device: object, token: string, replaced: boolean }}
 */
export function mintDevice(store, label, options = {}) {
  const normalized = normalizeLabel(label)
  const key = labelKey(normalized)
  const clientKind = typeof options.clientKind === 'string' && options.clientKind !== '' ? options.clientKind : null
  const ttlDays = Number.isFinite(options.ttlDays) && options.ttlDays > 0 ? options.ttlDays : null
  const now = new Date()
  const expiresAt = ttlDays === null ? null : new Date(now.getTime() + ttlDays * 86_400_000).toISOString()
  const token = generateToken()
  const existing = store.devices.find((device) => labelKey(device.label) === key)
  if (existing !== undefined) {
    existing.tokenHash = hashToken(token)
    existing.revokedAt = null
    existing.expiresAt = expiresAt
    existing.clientKind = clientKind ?? existing.clientKind
    return { device: existing, token, replaced: true }
  }
  if (store.devices.length >= (Number.isFinite(options.maxDevices) && options.maxDevices > 0 ? options.maxDevices : 64)) {
    throw new Error('device-auth: device limit reached; revoke an unused device first')
  }
  const device = {
    id: generateDeviceId(),
    label: normalized,
    tokenHash: hashToken(token),
    createdAt: now.toISOString(),
    expiresAt,
    revokedAt: null,
    clientKind,
  }
  store.devices.push(device)
  return { device, token, replaced: false }
}

/** Revoke one device; returns undefined when no device matches. */
export function revokeDevice(store, key) {
  const device = findDevice(store, key)
  if (device === undefined) return undefined
  if (device.revokedAt === null) device.revokedAt = new Date().toISOString()
  return device
}

/** Revoke every active device; returns how many changed. */
export function revokeAllDevices(store) {
  const now = new Date().toISOString()
  let changed = 0
  for (const device of store.devices) {
    if (device.revokedAt !== null) continue
    device.revokedAt = now
    changed += 1
  }
  return changed
}

/** Drop revoked records, keeping the file small; returns how many were removed. */
export function purgeRevokedDevices(store) {
  const before = store.devices.length
  store.devices = store.devices.filter((device) => device.revokedAt === null)
  return before - store.devices.length
}

/** Public (hash-free) view of one device, as printed by the CLI. */
export function publicDevice(device, now = Date.now()) {
  return {
    id: device.id,
    label: device.label,
    clientKind: device.clientKind ?? null,
    createdAt: device.createdAt,
    expiresAt: device.expiresAt ?? null,
    revokedAt: device.revokedAt ?? null,
    status: device.revokedAt !== null ? 'revoked' : isActiveDevice(device, now) ? 'active' : 'expired',
  }
}
