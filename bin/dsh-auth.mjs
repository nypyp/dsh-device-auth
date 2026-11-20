#!/usr/bin/env node
/**
 * dsh-auth — manage per-device credentials for the DSH Web UI.
 *
 * The token printed by `add` / `rotate` is shown exactly once: the store keeps
 * only its SHA-256 digest, so a lost token is rotated, never recovered.
 *
 * Usage:
 *   dsh-auth add <label> [--kind <name>] [--ttl-days <n>] [--origin <url>] [--json]
 *   dsh-auth rotate <label|id> [--ttl-days <n>] [--origin <url>] [--json]
 *   dsh-auth revoke <label|id> [--json]
 *   dsh-auth revoke --all [--json]
 *   dsh-auth list [--json]
 *   dsh-auth purge [--json]
 *
 * Global options:
 *   --store <path>   store file (default: $DSH_HOME/remote-auth.json, else ~/.dsh/remote-auth.json)
 *   --json           machine-readable output
 *   --origin <url>   URL origin printed in the login links (default: http://127.0.0.1:3080)
 */
import { realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import {
  findDevice,
  mintDevice,
  normalizeStore,
  publicDevice,
  purgeRevokedDevices,
  readStoreFile,
  resolveStorePath,
  revokeAllDevices,
  revokeDevice,
  withStoreLock,
  writeStoreFile,
} from '../lib/store.mjs'

const HELP = `dsh-auth — manage per-device credentials for the DSH Web UI

Commands:
  add <label>              mint a durable token for one device (re-pair rotates it)
  rotate <label|id>        mint a fresh token for an existing device
  revoke <label|id>        revoke one device immediately
  revoke --all             revoke every device
  list                     show devices (label, status, dates)
  purge                    drop revoked records from the store

Options:
  --store <path>           store file (default $DSH_HOME/remote-auth.json)
  --origin <url>           origin used in printed login links (default http://127.0.0.1:3080)
  --kind <name>            free-form client kind recorded with the device
  --ttl-days <n>           optional lifetime; the token expires after n days
  --json                   machine-readable output
  -h, --help               show this help

The token is printed once and stored only as a SHA-256 digest. To recover a
lost token, run "dsh-auth rotate <label>".`

function parseArgs(argv) {
  const options = { origin: 'http://127.0.0.1:3080', json: false, kind: undefined, ttlDays: undefined, store: undefined, all: false }
  const positional = []
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    const next = () => {
      index += 1
      if (index >= argv.length) throw new Error(`missing value for ${arg}`)
      return argv[index]
    }
    if (arg === '--json') options.json = true
    else if (arg === '--all') options.all = true
    else if (arg === '--store') options.store = next()
    else if (arg === '--origin') options.origin = next()
    else if (arg === '--kind') options.kind = next()
    else if (arg === '--ttl-days') {
      const value = Number(next())
      if (!Number.isFinite(value) || value <= 0) throw new Error('--ttl-days must be a positive number')
      options.ttlDays = value
    } else if (arg === '-h' || arg === '--help') return { help: true, options }
    else if (arg.startsWith('-')) throw new Error(`unknown option: ${arg}`)
    else positional.push(arg)
  }
  return { command: positional[0], args: positional.slice(1), options }
}

function block(label, token, origin) {
  const base = origin.replace(/\/+$/u, '')
  return {
    token,
    connectUrl: `${base}/connect?token=${encodeURIComponent(token)}`,
    browserUrl: `${base}/?token=${encodeURIComponent(token)}`,
    label,
  }
}

function printMint(device, token, origin, json) {
  const value = publicDevice(device)
  const links = block(value.label, token, origin)
  if (json) {
    console.log(JSON.stringify({ device: value, ...links }, null, 2))
    return
  }
  console.log(`device: ${value.label} (${value.id}) status=${value.status}`)
  console.log(`token (shown once): ${token}`)
  console.log(`app connect link:   ${links.connectUrl}`)
  console.log(`browser login link: ${links.browserUrl}`)
  if (value.expiresAt !== null) console.log(`expires: ${value.expiresAt}`)
}

function printList(devices, json) {
  const values = devices.map((device) => publicDevice(device))
  if (json) {
    console.log(JSON.stringify({ devices: values }, null, 2))
    return
  }
  if (values.length === 0) {
    console.log('no devices registered; run "dsh-auth add <label>"')
    return
  }
  for (const device of values) {
    const expires = device.expiresAt === null ? '' : ` expires=${device.expiresAt}`
    const revoked = device.revokedAt === null ? '' : ` revoked=${device.revokedAt}`
    console.log(`${device.label}\t${device.id}\t${device.status}\tcreated=${device.createdAt}${expires}${revoked}`)
  }
}

async function main(argv) {
  const parsed = parseArgs(argv)
  if (parsed.help === true) {
    console.log(HELP)
    return 0
  }
  const storePath = resolveStorePath(parsed.options.store)
  const { command, args, options } = parsed
  if (command === undefined) throw new Error(`missing command\n\n${HELP}`)

  if (command === 'list') {
    const { store } = readStoreFile(storePath)
    printList(store.devices, options.json)
    return 0
  }

  if (command === 'purge') {
    const removed = await withStoreLock(storePath, async () => {
      const { store } = readStoreFile(storePath)
      const count = purgeRevokedDevices(store)
      if (count > 0) writeStoreFile(storePath, store)
      return count
    })
    if (options.json) console.log(JSON.stringify({ removed }))
    else console.log(`removed ${String(removed)} revoked record(s) from ${storePath}`)
    return 0
  }

  if (command === 'revoke') {
    if (options.all === true) {
      const count = await withStoreLock(storePath, async () => {
        const { store } = readStoreFile(storePath)
        const changed = revokeAllDevices(store)
        if (changed > 0) writeStoreFile(storePath, store)
        return changed
      })
      if (options.json) console.log(JSON.stringify({ revoked: count }))
      else console.log(`revoked ${String(count)} device(s)`)
      return 0
    }
  }

  const label = args[0]

  if (command === 'add') {
    if (label === undefined || label.trim() === '') throw new Error('add requires a label, e.g. "dsh-auth add phone"')
    const created = await withStoreLock(storePath, async () => {
      const { store } = readStoreFile(storePath)
      const minted = mintDevice(store, label, { clientKind: options.kind, ttlDays: options.ttlDays })
      writeStoreFile(storePath, store)
      return minted
    })
    printMint(created.device, created.token, options.origin, options.json)
    return 0
  }

  if (command === 'rotate') {
    if (label === undefined || label.trim() === '') throw new Error('rotate requires a device label or id')
    const rotated = await withStoreLock(storePath, async () => {
      const { store } = readStoreFile(storePath)
      const existing = findDevice(store, label)
      if (existing === undefined) throw new Error(`no device matches ${JSON.stringify(label)}`)
      const minted = mintDevice(store, existing.label, { clientKind: options.kind ?? existing.clientKind ?? undefined, ttlDays: options.ttlDays })
      writeStoreFile(storePath, store)
      return minted
    })
    printMint(rotated.device, rotated.token, options.origin, options.json)
    return 0
  }

  if (command === 'revoke') {
    if (label === undefined || label.trim() === '') throw new Error('revoke requires a device label, id, or --all')
    const revoked = await withStoreLock(storePath, async () => {
      const { store } = readStoreFile(storePath)
      const device = revokeDevice(store, label)
      if (device === undefined) throw new Error(`no device matches ${JSON.stringify(label)}`)
      writeStoreFile(storePath, store)
      return device
    })
    if (options.json) console.log(JSON.stringify({ device: publicDevice(revoked) }))
    else console.log(`revoked ${revoked.label} (${revoked.id}); its next request is rejected immediately`)
    return 0
  }

  throw new Error(`unknown command ${JSON.stringify(command)}\n\n${HELP}`)
}

const invokedDirectly = (() => {
  if (process.argv[1] === undefined) return false
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return false
  }
})()
if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code },
    (error) => {
      console.error(`dsh-auth: ${error instanceof Error ? error.message : String(error)}`)
      process.exitCode = 1
    },
  )
}

export { main }
