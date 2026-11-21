/**
 * dsh-device-auth — stable, revocable per-device credentials for the DSH Web UI.
 *
 * DeepSeek Harness mints one random launch token per process and exposes it
 * only through the startup URL, so every paired remote client breaks on
 * restart. This plugin adds a durable credential layer *without* touching the
 * installed Harness packages:
 *
 * - It reads device token hashes from a store file (`remote-auth.json`), and
 *   wraps the live `connection` service instance methods `authorizeConnect` /
 *   `authorizeIndex`. Their callers dispatch dynamically per request, so a
 *   wrapper is enough to accept additional tokens. A matching device token is
 *   swapped for this process's real launch token and the original
 *   implementation runs unchanged: the Host/Origin fence, the 302/303
 *   redirect, the signed cookie, the audience binding and the 30-day lifetime
 *   all stay the original ones.
 *
 * - It indexes every cookie minted during a device exchange by its hash and
 *   device id (`remote-auth-sessions.json`), and wraps `admit` plus
 *   `authorizeIndex` to reject a session whose device was revoked. That makes
 *   revocation immediate for the revoked device, while cookies minted with the
 *   real launch token (or before this plugin existed) keep working unchanged.
 *
 * Everything else (the printed launch URL, the browser cookie flow, the
 * trusted-host fence, `--public-url`) behaves exactly as before; unknown
 * tokens are delegated untouched. Because the plugin lives in the user's
 * profile it survives `npm i -g @deepseek-ai/dsh@<next>` upgrades, and it fails
 * loudly instead of silently degrading when a future Harness version stops
 * exposing the wrapped methods.
 *
 * The device store is only read here. Mutations (add/rotate/revoke) are made by
 * the `dsh-auth` CLI under a cross-process lock, so a stale in-process snapshot
 * can never resurrect a revoked device. The session index is a derived cache:
 * it only ever grants a rejection, never authentication, so a lost or racy
 * write degrades to "cookie delegated to the original check" rather than to a
 * bypass.
 */
import { readFileSync, statSync } from 'node:fs'

import {
  TOKEN_PREFIX,
  findActiveDevice,
  isActiveDevice,
  normalizeStore,
} from './store.mjs'
import {
  cookieHeaderOf,
  cookiePairsFromHeader,
  hashCookiePair,
  mergeSession,
  readSessionsFile,
  resolveSessionsPath,
  sessionFromSetCookie,
  writeSessionsFile,
} from './sessions.mjs'

/** Stable Cordis plugin name. */
export const name = 'device-auth'

/** The connection service must exist before the wrappers can be installed. */
export const inject = ['connection']

/** Base used only to parse request URLs and the authenticated launch URL. */
const URL_BASE = 'http://dsh.invalid'

/** Cache key from nanosecond mtime and size; undefined when the file is absent. */
function fileKey(path) {
  try {
    const stat = statSync(path, { bigint: true })
    return `${String(stat.mtimeNs)}:${String(stat.size)}`
  } catch {
    return undefined
  }
}

/** Extract the single `token` query value from a path or absolute URL. */
function tokenFromUrl(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl === '') return undefined
  let url
  try {
    url = new URL(rawUrl, URL_BASE)
  } catch {
    return undefined
  }
  const values = url.searchParams.getAll('token')
  return values.length === 1 ? values[0] : undefined
}

/** Return `rawUrl` with its token query swapped, preserving its absolute/relative shape. */
function withToken(rawUrl, token) {
  const url = new URL(rawUrl, URL_BASE)
  url.searchParams.set('token', token)
  const absolute = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawUrl)
  return absolute ? url.href : `${url.pathname}${url.search}`
}

/** Clone a Fetch `Request` (or an IncomingMessage-like object) with a rewritten URL. */
function withRewrittenRequest(request, token) {
  const nextUrl = withToken(request.url, token)
  if (typeof Request !== 'undefined' && request instanceof Request) {
    return new Request(nextUrl, { method: request.method, headers: request.headers })
  }
  return { ...request, url: nextUrl }
}

/** Collect `Set-Cookie` values written by one call while letting it run normally. */
function captureSetCookies(response, run) {
  const originalWriteHead = response?.writeHead
  if (typeof originalWriteHead !== 'function') return { cookies: [], result: run() }
  const cookies = []
  response.writeHead = function captureWriteHead(status, headers, ...rest) {
    const value = headers?.['set-cookie'] ?? headers?.['Set-Cookie']
    if (Array.isArray(value)) for (const entry of value) cookies.push(String(entry))
    else if (value !== undefined) cookies.push(String(value))
    return originalWriteHead.call(this, status, headers, ...rest)
  }
  try {
    const result = run()
    return { cookies, result }
  } finally {
    response.writeHead = originalWriteHead
  }
}

/**
 * Install the plugin.
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {{ storePath: string, sessionsPath?: string, prefix?: string }} config
 */
export function apply(ctx, config) {
  const storePath = typeof config?.storePath === 'string' ? config.storePath.trim() : ''
  if (storePath === '') {
    throw new Error('device-auth: config.storePath must name the device credential store (use !!js dshHomePath(\'remote-auth.json\'))')
  }
  const sessionsPath = resolveSessionsPath(storePath, config?.sessionsPath)
  const prefix = typeof config?.prefix === 'string' && config.prefix !== '' ? config.prefix : TOKEN_PREFIX

  /** Last device-store snapshot, keyed by mtime+size so a CLI mutation is visible on the next request. */
  let snapshot = { key: undefined, devices: [], exists: false }
  let sessionSnapshot = { key: undefined, sessions: [] }
  let warnedAt = 0
  const warn = (message) => {
    const now = Date.now()
    if (now - warnedAt < 60_000) return
    warnedAt = now
    console.warn(`device-auth: ${message}`)
  }

  /** Read device records, fail closed (no devices) on an unreadable store. */
  const devices = () => {
    const key = fileKey(storePath)
    if (key === undefined) {
      snapshot = { key: 'missing', devices: [], exists: false }
      return snapshot.devices
    }
    if (snapshot.key === key) return snapshot.devices
    try {
      const store = normalizeStore(JSON.parse(readFileSync(storePath, 'utf8')))
      snapshot = { key, devices: store.devices, exists: true }
      return snapshot.devices
    } catch (error) {
      warn(`ignoring unreadable store ${storePath}: ${error.message}`)
      snapshot = { key, devices: [], exists: true }
      return snapshot.devices
    }
  }

  /** Read device records without the cache: revocation must be visible on the very next request. */
  const devicesFresh = () => {
    try {
      return normalizeStore(JSON.parse(readFileSync(storePath, 'utf8'))).devices
    } catch (error) {
      if (error?.code !== 'ENOENT') warn(`cannot read ${storePath}: ${error.message}`)
      return []
    }
  }

  /** Read the cookie→device index, cached by nanosecond mtime and size. */
  const sessions = () => {
    const key = fileKey(sessionsPath)
    if (key === undefined) {
      sessionSnapshot = { key: 'missing', sessions: [] }
      return sessionSnapshot.sessions
    }
    if (sessionSnapshot.key === key) return sessionSnapshot.sessions
    try {
      const { sessions: records } = readSessionsFile(sessionsPath)
      sessionSnapshot = { key, sessions: records }
      return records
    } catch (error) {
      warn(`ignoring session index ${sessionsPath}: ${error.message}`)
      sessionSnapshot = { key, sessions: [] }
      return sessionSnapshot.sessions
    }
  }

  /** Map a presented request's cookies to a device that is no longer active. */
  const revokedDeviceOf = (request) => {
    const pairs = cookiePairsFromHeader(cookieHeaderOf(request))
    if (pairs.length === 0) return undefined
    const index = sessions()
    if (index.length === 0) return undefined
    const byHash = new Map()
    for (const session of index) {
      const mapped = byHash.get(session.cookieHash)
      if (mapped === undefined) byHash.set(session.cookieHash, [session.deviceId])
      else if (!mapped.includes(session.deviceId)) mapped.push(session.deviceId)
    }
    const records = devicesFresh()
    for (const pair of pairs) {
      const deviceIds = byHash.get(hashCookiePair(pair))
      if (deviceIds === undefined) continue
      for (const deviceId of deviceIds) {
        const device = records.find((record) => record.id === deviceId)
        if (device === undefined || !isActiveDevice(device)) return deviceId
      }
    }
    return undefined
  }

  /** Record the cookies just minted for a device exchange; failures never block the response. */
  const recordMintedSessions = (setCookies, deviceId) => {
    if (!Array.isArray(setCookies) || setCookies.length === 0) return
    try {
      const { sessions: current } = readSessionsFile(sessionsPath)
      let changed = false
      for (const setCookie of setCookies) {
        const parsed = sessionFromSetCookie(setCookie)
        if (parsed === undefined) continue
        const entry = {
          cookieHash: hashCookiePair(parsed.pair),
          deviceId,
          issuedAt: new Date().toISOString(),
          expiresAt: parsed.expiresAt,
        }
        if (mergeSession(current, entry)) changed = true
      }
      if (changed) {
        writeSessionsFile(sessionsPath, current)
        sessionSnapshot = { key: fileKey(sessionsPath) ?? 'written', sessions: current }
      }
    } catch (error) {
      warn(`could not record sessions for ${deviceId}: ${error instanceof Error ? error.message : String(error)}`)
    }
  }

  /** The current process's real launch token, read through the documented service method. */
  const launchToken = (connection) => {
    try {
      const url = new URL(connection.authenticatedUrl(`${URL_BASE}/`))
      return url.searchParams.get('token') ?? undefined
    } catch {
      return undefined
    }
  }

  /** A device token matching an active record, or undefined. */
  const matchedDevice = (presented) => {
    if (typeof presented !== 'string' || !presented.startsWith(prefix)) return undefined
    return findActiveDevice({ devices: devices() }, presented)
  }

  let wrappedConnection
  let restoreWrappers

  const ensureWrapped = () => {
    const connection = ctx.get('connection')
    if (connection === undefined || connection === null) return
    if (wrappedConnection === connection) return

    const originalConnect = connection.authorizeConnect
    const originalIndex = connection.authorizeIndex
    const originalAdmit = connection.admit
    if (typeof originalConnect !== 'function' || typeof originalIndex !== 'function' || typeof originalAdmit !== 'function') {
      throw new Error('device-auth: unsupported Harness version: the connection service no longer exposes authorizeConnect/authorizeIndex/admit; refusing to activate a silent no-op')
    }

    const wrappedConnect = function deviceAuthorizeConnect(request, response) {
      const device = matchedDevice(tokenFromUrl(request?.url))
      const token = device === undefined ? undefined : launchToken(connection)
      if (token === undefined || typeof request?.url !== 'string') {
        return originalConnect.call(connection, request, response)
      }
      const originalUrl = request.url
      const { cookies, result } = captureSetCookies(response, () => {
        try {
          request.url = withToken(originalUrl, token)
          return originalConnect.call(connection, request, response)
        } finally {
          request.url = originalUrl
        }
      })
      recordMintedSessions(cookies, device.id)
      return result
    }

    const wrappedIndex = function deviceAuthorizeIndex(request, response, secure) {
      if (revokedDeviceOf(request) !== undefined) {
        response.writeHead(401, { 'cache-control': 'no-store' })
        response.end('unauthorized')
        return false
      }
      const device = matchedDevice(tokenFromUrl(request?.url))
      const token = device === undefined ? undefined : launchToken(connection)
      if (token === undefined || typeof request?.url !== 'string') {
        return originalIndex.call(connection, request, response, secure)
      }
      const { cookies, result } = captureSetCookies(response, () =>
        originalIndex.call(connection, withRewrittenRequest(request, token), response, secure))
      recordMintedSessions(cookies, device.id)
      return result
    }

    const wrappedAdmit = function deviceAdmit(request) {
      if (revokedDeviceOf(request) !== undefined) return { rejection: 401 }
      return originalAdmit.call(connection, request)
    }

    connection.authorizeConnect = wrappedConnect
    connection.authorizeIndex = wrappedIndex
    connection.admit = wrappedAdmit
    wrappedConnection = connection
    restoreWrappers = () => {
      if (connection.authorizeConnect === wrappedConnect) connection.authorizeConnect = originalConnect
      if (connection.authorizeIndex === wrappedIndex) connection.authorizeIndex = originalIndex
      if (connection.admit === wrappedAdmit) connection.admit = originalAdmit
      wrappedConnection = undefined
      restoreWrappers = undefined
    }
  }

  ctx.effect(() => {
    ensureWrapped()
    // A profile config reload may replace the connection plugin instance.
    const off = ctx.on('app-boot/config-reload', () => {
      try {
        ensureWrapped()
      } catch (error) {
        console.error(`device-auth: ${error instanceof Error ? error.message : String(error)}`)
      }
    })
    return () => {
      off?.()
      restoreWrappers?.()
    }
  }, 'device-auth: connection authorization wrapper')
}
