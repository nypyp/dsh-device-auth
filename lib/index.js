/**
 * dsh-device-auth — stable, revocable per-device credentials for the DSH Web UI.
 *
 * DeepSeek Harness mints one random launch token per process and exposes it
 * only through the startup URL, so every paired remote client breaks on
 * restart. This plugin adds a durable credential layer *without* touching the
 * installed Harness packages:
 *
 * - It reads device token hashes from a store file (`remote-auth.json`),
 * - and wraps the live `connection` service instance methods
 *   `authorizeConnect` / `authorizeIndex`. The clients of those services call
 *   them dynamically per request, so subscribing a wrapper is enough to accept
 *   additional tokens. A matching device token is swapped for this process's
 *   real launch token and the original implementation runs unchanged: the
 *   Host/Origin fence, the 302/303 redirect, the signed cookie, the cookie
 *   audience binding and the 30-day lifetime all stay the original ones.
 *
 * Everything else (the printed launch URL, the browser cookie flow, the
 * trusted-host fence, `--public-url`) behaves exactly as before; unknown
 * tokens are delegated untouched. Because the plugin lives in the user's
 * profile it survives `npm i -g @deepseek-ai/dsh@<next>` upgrades, and it fails
 * loudly instead of silently degrading when a future Harness version stops
 * exposing the wrapped methods.
 *
 * The store is only read here. Mutations (add/rotate/revoke) are made by the
 * `dsh-auth` CLI under a cross-process lock, so a stale in-process snapshot can
 * never resurrect a revoked device.
 */
import { readFileSync, statSync } from 'node:fs'

import {
  TOKEN_PREFIX,
  findActiveDevice,
  normalizeStore,
} from './store.mjs'

/** Stable Cordis plugin name. */
export const name = 'device-auth'

/** The connection service must exist before the wrapper can be installed. */
export const inject = ['connection']

/** Base used only to parse request URLs and the authenticated launch URL. */
const URL_BASE = 'http://dsh.invalid'

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

/**
 * Install the plugin.
 * @param {import('@deepseek-ai/cordis').Context} ctx
 * @param {{ storePath: string, prefix?: string }} config
 */
export function apply(ctx, config) {
  const storePath = typeof config?.storePath === 'string' ? config.storePath.trim() : ''
  if (storePath === '') {
    throw new Error('device-auth: config.storePath must name the device credential store (use !!js dshHomePath(\'remote-auth.json\'))')
  }
  const prefix = typeof config?.prefix === 'string' && config.prefix !== '' ? config.prefix : TOKEN_PREFIX

  /** Last store snapshot, keyed by mtime+size so a CLI mutation is visible on the next request. */
  let snapshot = { key: undefined, devices: [], exists: false }
  let warnedAt = 0
  const warn = (message) => {
    const now = Date.now()
    if (now - warnedAt < 60_000) return
    warnedAt = now
    console.warn(`device-auth: ${message}`)
  }

  /** Read device records, fail closed (no devices) on an unreadable store. */
  const devices = () => {
    let stat
    try {
      stat = statSync(storePath)
    } catch (error) {
      if (error?.code === 'ENOENT') {
        snapshot = { key: 'missing', devices: [], exists: false }
        return snapshot.devices
      }
      warn(`cannot stat ${storePath}: ${error.message}`)
      return snapshot.devices
    }
    const key = `${String(stat.mtimeMs)}:${String(stat.size)}`
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
    if (typeof originalConnect !== 'function' || typeof originalIndex !== 'function') {
      throw new Error('device-auth: unsupported Harness version: the connection service does not expose authorizeConnect/authorizeIndex; refusing to activate a silent no-op')
    }

    const wrappedConnect = function deviceAuthorizeConnect(request, response) {
      const device = matchedDevice(tokenFromUrl(request?.url))
      const token = device === undefined ? undefined : launchToken(connection)
      if (token === undefined || typeof request?.url !== 'string') {
        return originalConnect.call(connection, request, response)
      }
      const originalUrl = request.url
      try {
        request.url = withToken(originalUrl, token)
        return originalConnect.call(connection, request, response)
      } finally {
        request.url = originalUrl
      }
    }

    const wrappedIndex = function deviceAuthorizeIndex(request, response, secure) {
      const device = matchedDevice(tokenFromUrl(request?.url))
      const token = device === undefined ? undefined : launchToken(connection)
      if (token === undefined || typeof request?.url !== 'string') {
        return originalIndex.call(connection, request, response, secure)
      }
      return originalIndex.call(connection, withRewrittenRequest(request, token), response, secure)
    }
    connection.authorizeConnect = wrappedConnect
    connection.authorizeIndex = wrappedIndex
    wrappedConnection = connection
    restoreWrappers = () => {
      if (connection.authorizeConnect === wrappedConnect) connection.authorizeConnect = originalConnect
      if (connection.authorizeIndex === wrappedIndex) connection.authorizeIndex = originalIndex
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
