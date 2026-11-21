/**
 * Unit tests for the store and the authorization wrapper. They do not need a
 * running Harness: a fake connection service reproduces the two behaviours the
 * wrapper must preserve (token comparison, redirect + cookie, index serving).
 *
 * Run: node --test plugins/dsh-device-auth/test/unit.test.mjs
 */
import assert from 'node:assert/strict'
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  TOKEN_PREFIX,
  findActiveDevice,
  findDevice,
  mintDevice,
  normalizeStore,
  purgeRevokedDevices,
  readStoreFile,
  revokeAllDevices,
  revokeDevice,
  withStoreLock,
  writeStoreFile,
  hashToken,
} from '../lib/store.mjs'
import { apply } from '../lib/index.js'
import {
  cookiePairsFromHeader,
  hashCookiePair,
  mergeSession,
  readSessionsFile,
  removeSessionsForDevice,
  resolveSessionsPath,
  pruneSessions,
  sessionFromSetCookie,
  writeSessionsFile,
} from '../lib/sessions.mjs'

const REAL_TOKEN = 'ZcUjRealProcessLaunchToken0123456789abcdefghij'

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), 'dsh-device-auth-unit-'))
  chmodSync(root, 0o700)
  return { root, storePath: join(root, 'remote-auth.json') }
}

function mint(storePath, label, options) {
  const { store } = readStoreFile(storePath)
  const minted = mintDevice(store, label, options)
  writeStoreFile(storePath, store)
  return minted
}

/** A minimal connection service that behaves like the shipped one for the tested paths. */
function fakeConnection(realToken = REAL_TOKEN) {
  const calls = { connect: [], index: [], admit: [] }
  let minted = 0
  const connection = {
    authenticatedUrl(baseUrl) {
      const url = new URL(baseUrl)
      url.searchParams.set('token', realToken)
      return url.href
    },
    authorizeConnect(request, response) {
      calls.connect.push({ url: request.url, host: request.headers?.host })
      const url = new URL(request.url, 'http://dsh.invalid')
      const tokens = url.searchParams.getAll('token')
      if (url.pathname !== '/connect' || tokens.length !== 1 || tokens[0] !== realToken) {
        response.writeHead(401)
        response.end('unauthorized')
        return
      }
      minted += 1
      response.writeHead(302, { location: './api/remote.mux', 'set-cookie': `dsh-auth-test=cookie-${String(minted)}` })
      response.end()
    },
    admit(request) {
      const cookie = request.headers instanceof Headers ? request.headers.get('cookie') : request.headers?.cookie
      calls.admit.push(cookie ?? null)
      if (typeof cookie === 'string' && cookie.includes('dsh-auth-test=')) return { peer: { id: 'browser' } }
      return { rejection: 401 }
    },
    authorizeIndex(request, response) {
      calls.index.push({ url: request.url, host: request.headers instanceof Headers ? request.headers.get('host') : request.headers?.host })
      const url = new URL(request.url, 'http://dsh.invalid')
      const tokens = url.searchParams.getAll('token')
      if (tokens.length > 0 && tokens[0] === realToken && request.method === 'GET') {
        response.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-test=1' })
        response.end()
        return false
      }
      response.writeHead(401)
      response.end('unauthorized')
      return false
    },
  }
  return { connection, calls }
}

function fakeCtx(connection) {
  const disposers = []
  return {
    ctx: {
      get(name) {
        return name === 'connection' ? connection : undefined
      },
      effect(factory) {
        disposers.push(factory())
      },
      on() {
        return () => {}
      },
    },
    dispose() {
      for (const dispose of disposers.splice(0).reverse()) dispose?.()
    },
  }
}

function responseSpy() {
  const response = { status: 0, headers: {}, body: '' }
  response.writeHead = (status, headers) => { response.status = status; Object.assign(response.headers, headers ?? {}) }
  response.end = (body) => { response.body = body ?? '' }
  return response
}

test('store: mint persists only a sha256 hash and keeps the file private', () => {
  const { root, storePath } = sandbox()
  try {
    const { device, token } = mint(storePath, 'phone')
    assert.ok(token.startsWith(TOKEN_PREFIX))
    assert.equal(token.length, TOKEN_PREFIX.length + 43)
    assert.ok(token.startsWith(TOKEN_PREFIX))
    const raw = readFileSync(storePath, 'utf8')
    assert.ok(!raw.includes(token), 'plaintext token must not be persisted')
    assert.ok(raw.includes(hashToken(token)), 'store keeps the digest')
    assert.equal(statSync(storePath).mode & 0o777, 0o600)
    assert.equal(statSync(root).mode & 0o777, 0o700)
    assert.equal(device.label, 'phone')
    assert.deepEqual(device, normalizeStore(JSON.parse(raw)).devices[0])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('store: matching is exact, constant-time safe, and rejects foreign tokens', () => {
  const { root, storePath } = sandbox()
  try {
    const { token } = mint(storePath, 'phone')
    const { store } = readStoreFile(storePath)
    assert.ok(findActiveDevice(store, token) !== undefined)
    assert.equal(findActiveDevice(store, `${token}x`), undefined)
    assert.equal(findActiveDevice(store, 'not-a-device-token'), undefined)
    assert.equal(findActiveDevice(store, REAL_TOKEN), undefined)
    assert.equal(findActiveDevice(store, ''), undefined)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('store: re-mint for the same label rotates in place and invalidates the old token', () => {
  const { root, storePath } = sandbox()
  try {
    const first = mint(storePath, 'phone')
    const second = mint(storePath, 'Phone') // case-insensitive dedupe
    assert.equal(second.replaced, true)
    assert.equal(second.device.id, first.device.id)
    assert.equal(second.device.createdAt, first.device.createdAt)
    const { store } = readStoreFile(storePath)
    assert.equal(store.devices.length, 1)
    assert.ok(findActiveDevice(store, second.token) !== undefined)
    assert.equal(findActiveDevice(store, first.token), undefined)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('store: revoke is immediate and purge removes the record', () => {
  const { root, storePath } = sandbox()
  try {
    const { token, device } = mint(storePath, 'phone')
    {
      const { store } = readStoreFile(storePath)
      assert.notEqual(revokeDevice(store, device.id), undefined)
      writeStoreFile(storePath, store)
    }
    let { store } = readStoreFile(storePath)
    assert.equal(findActiveDevice(store, token), undefined)
    assert.equal(findDevice(store, 'phone').status, undefined)
    {
      const before = store.devices.length
      assert.equal(purgeRevokedDevices(store), before)
      writeStoreFile(storePath, store)
    }
    store = readStoreFile(storePath).store
    assert.equal(store.devices.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('store: revoke --all and ttl expiry', () => {
  const { root, storePath } = sandbox()
  try {
    mint(storePath, 'one')
    mint(storePath, 'two')
    const { store } = readStoreFile(storePath)
    assert.equal(revokeAllDevices(store), 2)
    writeStoreFile(storePath, store)
    const reloaded = readStoreFile(storePath).store
    assert.ok(reloaded.devices.every((device) => device.revokedAt !== null))

    const expired = mint(storePath, 'three', { ttlDays: 0.001 })
    assert.ok(expired.device.expiresAt !== null)
    const check = normalizeStore({ devices: [{ ...expired.device, tokenHash: hashToken(expired.token), expiresAt: '2000-01-01T00:00:00.000Z' }] })
    assert.equal(findActiveDevice(check, expired.token), undefined)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('store: mutations are serialized across concurrent writers', async () => {
  const { root, storePath } = sandbox()
  try {
    await Promise.all(Array.from({ length: 8 }, (_, index) => withStoreLock(storePath, async () => {
      const { store } = readStoreFile(storePath)
      mintDevice(store, `device-${String(index)}`)
      writeStoreFile(storePath, store)
    })))
    const { store } = readStoreFile(storePath)
    assert.equal(store.devices.length, 8)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('wrapper: device tokens are swapped for the real launch token, others are untouched', () => {
  const { root, storePath } = sandbox()
  try {
    const { token } = mint(storePath, 'phone')
    const { connection, calls } = fakeConnection()
    const originalConnect = connection.authorizeConnect
    const originalIndex = connection.authorizeIndex
    const { ctx, dispose } = fakeCtx(connection)
    apply(ctx, { storePath })
    try {
      // A device token reaches the original implementation already substituted.
      const ok = responseSpy()
      connection.authorizeConnect({ url: `/connect?token=${token}`, headers: { host: '127.0.0.1:3099' } }, ok)
      assert.equal(ok.status, 302)
      assert.match(ok.headers['set-cookie'], /^dsh-auth-test=cookie-/u)
      assert.equal(calls.connect.at(-1).url, `/connect?token=${REAL_TOKEN}`)
      // The wrapper restores the incoming URL afterwards.
      const request = { url: `/connect?token=${token}`, headers: { host: '127.0.0.1:3099' } }
      connection.authorizeConnect(request, responseSpy())
      assert.equal(request.url, `/connect?token=${token}`)

      // Unknown tokens and the real launch token delegate unchanged.
      const wrong = responseSpy()
      connection.authorizeConnect({ url: '/connect?token=bogus', headers: { host: '127.0.0.1:3099' } }, wrong)
      assert.equal(wrong.status, 401)
      const real = responseSpy()
      connection.authorizeConnect({ url: `/connect?token=${REAL_TOKEN}`, headers: { host: '127.0.0.1:3099' } }, real)
      assert.equal(real.status, 302)

      // The browser index flow accepts a device token and keeps the interactions query.
      const indexRequest = new Request(`http://127.0.0.1:3099/?token=${token}&x=1`, { headers: { host: '127.0.0.1:3099' } })
      const indexResponse = responseSpy()
      assert.equal(connection.authorizeIndex(indexRequest, indexResponse), false)
      assert.equal(indexResponse.status, 303)
      assert.equal(calls.index.at(-1).url, `http://127.0.0.1:3099/?token=${REAL_TOKEN}&x=1`)
      assert.equal(calls.index.at(-1).host, '127.0.0.1:3099')

      // Revocation is visible on the next request without a restart.
      {
        const { store } = readStoreFile(storePath)
        revokeDevice(store, 'phone')
        writeStoreFile(storePath, store)
      }
      const revoked = responseSpy()
      connection.authorizeConnect({ url: `/connect?token=${token}`, headers: { host: '127.0.0.1:3099' } }, revoked)
      assert.equal(revoked.status, 401)
    } finally {
      dispose()
    }
    // Unloading restores the original methods.
    assert.equal(connection.authorizeConnect, originalConnect)
    assert.equal(connection.authorizeIndex, originalIndex)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('wrapper: refuses to activate when the connection service changes shape', () => {
  const { root, storePath } = sandbox()
  try {
    const { connection } = fakeConnection()
    delete connection.authorizeIndex
    const { ctx } = fakeCtx(connection)
    assert.throws(() => apply(ctx, { storePath }), /no longer exposes authorizeConnect/u)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('sessions: Set-Cookie parsing, hashing and cookie-header parsing', () => {
  const parsed = sessionFromSetCookie('dsh-auth-abc=v1.payload.sig; Max-Age=2592000; Path=/; HttpOnly; SameSite=Strict', 1_000)
  assert.equal(parsed.pair, 'dsh-auth-abc=v1.payload.sig')
  assert.equal(parsed.expiresAt, new Date(1_000 + 2_592_000_000).toISOString())
  assert.equal(sessionFromSetCookie('no-equals'), undefined)
  assert.equal(parsed.pair.includes(';'), false)
  assert.equal(hashCookiePair(parsed.pair).length, 64)
  assert.deepEqual(cookiePairsFromHeader('a=1; dsh-auth-abc=v1.payload.sig'), ['a=1', 'dsh-auth-abc=v1.payload.sig'])
  assert.deepEqual(cookiePairsFromHeader(''), [])
})

test('sessions: index keeps hashes only, dedupes and prunes', () => {
  const { root, storePath } = sandbox()
  try {
    const sessionsPath = resolveSessionsPath(storePath)
    const now = Date.now()
    const sessions = []
    const entry = {
      cookieHash: hashCookiePair('dsh-auth-x=v1.a.b'),
      deviceId: 'dev_one',
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
    }
    assert.equal(mergeSession(sessions, entry), true)
    assert.equal(mergeSession(sessions, entry), false)
    assert.equal(sessions.length, 1)
    const expired = { ...entry, cookieHash: hashCookiePair('dsh-auth-y=old'), expiresAt: '2000-01-01T00:00:00.000Z' }
    assert.equal(mergeSession(sessions, expired), false)
    assert.equal(pruneSessions([...sessions, expired]).length, 1)
    writeSessionsFile(sessionsPath, sessions)
    const raw = readFileSync(sessionsPath, 'utf8')
    assert.ok(!raw.includes('dsh-auth-x=v1.a.b'), 'cookie plaintext must not be persisted')
    assert.ok(raw.includes(hashCookiePair('dsh-auth-x=v1.a.b')))
    assert.equal(statSync(sessionsPath).mode & 0o777, 0o600)
    assert.deepEqual(readSessionsFile(sessionsPath).sessions.length, 1)
    assert.equal(removeSessionsForDevice(sessions, 'dev_one'), 1)
    assert.equal(sessions.length, 0)
    assert.deepEqual(readSessionsFile(resolveSessionsPath(storePath, '/nonexistent/none.json')).sessions, [])
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('wrapper: revoked device session is rejected by admit and index', () => {
  const { root, storePath } = sandbox()
  try {
    const { token, device } = mint(storePath, 'phone')
    const { connection } = fakeConnection()
    const { ctx, dispose } = fakeCtx(connection)
    apply(ctx, { storePath })
    try {
      const connect = responseSpy()
      connection.authorizeConnect({ url: `/connect?token=${token}`, headers: { host: '127.0.0.1:3099' } }, connect)
      assert.equal(connect.status, 302)
      const cookie = connect.headers['set-cookie']
      assert.match(cookie, /^dsh-auth-test=cookie-/u)
      const sessionsPath = resolveSessionsPath(storePath)
      assert.equal(readSessionsFile(sessionsPath).sessions.length, 1, 'exchange records one session')
      assert.equal(hashCookiePair(cookie).length, 64)

      // Active device: delegate to the original admit (which accepts the cookie).
      assert.deepEqual(connection.admit({ headers: { cookie } }), { peer: { id: 'browser' } })
      // Unknown cookies are delegated, not judged by this plugin.
      assert.deepEqual(connection.admit({ headers: { cookie: 'other=1' } }), { rejection: 401 })

      // Revoke: the very next request with the already-minted cookie is refused.
      {
        const { store } = readStoreFile(storePath)
        revokeDevice(store, device.id)
        writeStoreFile(storePath, store)
      }
      assert.deepEqual(connection.admit({ headers: { cookie } }), { rejection: 401 })

      // The browser index path is refused too, with the original 401 shape.
      const indexResponse = responseSpy()
      const indexRequest = new Request('http://127.0.0.1:3099/', { headers: { cookie, host: '127.0.0.1:3099' } })
      assert.equal(connection.authorizeIndex(indexRequest, indexResponse), false)
      assert.equal(indexResponse.status, 401)

      // A live device is unaffected by another device's revocation.
      const other = mint(storePath, 'tablet')
      const otherConnect = responseSpy()
      connection.authorizeConnect({ url: `/connect?token=${other.token}`, headers: { host: '127.0.0.1:3099' } }, otherConnect)
      assert.equal(otherConnect.status, 302)
      assert.deepEqual(connection.admit({ headers: { cookie } }), { rejection: 401 })
    } finally {
      dispose()
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('wrapper: missing session index delegates to the original authentication', () => {
  const { root, storePath } = sandbox()
  try {
    const { connection } = fakeConnection()
    const { ctx, dispose } = fakeCtx(connection)
    apply(ctx, { storePath })
    try {
      // No sessions file at all: the wrapper must not invent a rejection.
      assert.deepEqual(connection.admit({ headers: { cookie: 'dsh-auth-test=1' } }), { peer: { id: 'browser' } })
      assert.deepEqual(connection.admit({}), { rejection: 401 })
    } finally {
      dispose()
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('wrapper: requires a store path', () => {
  const { connection } = fakeConnection()
  const { ctx } = fakeCtx(connection)
  assert.throws(() => apply(ctx, {}), /storePath/u)
})
