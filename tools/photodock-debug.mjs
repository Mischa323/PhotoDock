#!/usr/bin/env node
// Read-only troubleshooting client for a PhotoDock server's debug API.
//
// Setup: create a token in Settings → Debug access, then either export
//   PHOTODOCK_URL=https://photos.example.com  PHOTODOCK_DEBUG_TOKEN=pdd_…
// or put those two lines in .photodock-debug.env in the project root (it's
// git-ignored). The token is never printed.
//
// Usage: node tools/photodock-debug.mjs <command> [--option=value …] [--json]
//   overview                                  version, uptime, counts, served firmware
//   logs        [--level=warn|error] [--grep=text] [--since=15m|<ISO>] [--limit=200]
//   activity    [--event=name] [--limit=50]   the dashboard's activity log
//   devices                                   last check-in of every device + its settings
//   device-logs [--device=id] [--screen=id] [--entries=3]
//   screens                                   screens, albums, queues, keys
//   settings                                  settings, roles, users (no secrets)
//   updates                                   app + firmware vs GitHub
//   get <path>                                any GET under /api/debug/ (raw JSON)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadEnvFile() {
    for (const file of [path.join(process.cwd(), '.photodock-debug.env'), path.join(ROOT, '.photodock-debug.env')]) {
        if (!fs.existsSync(file)) continue;
        const out = {};
        for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
            const m = /^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/.exec(line);
            if (m) out[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
        }
        return out;
    }
    return {};
}

const fileEnv = loadEnvFile();
const BASE  = (process.env.PHOTODOCK_URL || fileEnv.PHOTODOCK_URL || '').replace(/\/+$/, '');
const TOKEN = process.env.PHOTODOCK_DEBUG_TOKEN || fileEnv.PHOTODOCK_DEBUG_TOKEN || '';

const [cmd, ...rest] = process.argv.slice(2);
const opts = {}, args = [];
for (const a of rest) {
    const m = /^--([\w-]+)(?:=(.*))?$/.exec(a);
    if (m) opts[m[1]] = m[2] ?? true; else args.push(a);
}

function fail(msg) { console.error(msg); process.exit(1); }

// "15m", "2h", "1d" → an ISO time that long ago; anything else is passed through.
function sinceParam(v) {
    const m = /^(\d+)([smhd])$/.exec(String(v));
    if (!m) return String(v);
    const ms = { s: 1e3, m: 6e4, h: 36e5, d: 864e5 }[m[2]] * Number(m[1]);
    return new Date(Date.now() - ms).toISOString();
}

async function get(endpoint, query = {}) {
    const qs = new URLSearchParams(Object.entries(query).filter(([, v]) => v !== undefined && v !== true).map(([k, v]) => [k, String(v)]));
    const url = `${BASE}/api/debug/${endpoint.replace(/^\/+/, '')}${qs.size ? '?' + qs : ''}`;
    let res;
    try {
        res = await fetch(url, { headers: { Authorization: `Bearer ${TOKEN}` }, signal: AbortSignal.timeout(20000) });
    } catch (e) {
        fail(`Could not reach ${BASE}: ${e.cause?.code || e.message}`);
    }
    const body = await res.json().catch(() => null);
    if (res.status === 401) fail('The debug token is invalid or has expired — create a new one in Settings → Debug access.');
    if (res.status === 404) fail(`${endpoint}: not found — is this PhotoDock version new enough for the debug API?`);
    if (!res.ok) fail(`HTTP ${res.status}: ${body?.error || res.statusText}`);
    return body;
}

const local = iso => iso ? new Date(iso).toLocaleString('nl-NL', { hour12: false }) : '—';
const print = v => console.log(JSON.stringify(v, null, 2));

const COMMANDS = {
    async overview() { print(await get('overview')); },

    async logs() {
        const list = await get('server-logs', { level: opts.level, grep: opts.grep, limit: opts.limit,
                                                since: opts.since && sinceParam(opts.since) });
        if (opts.json) return print(list);
        if (!list.length) return console.log('(no matching server log lines)');
        for (const e of list) console.log(`${local(e.t)}  ${e.level.toUpperCase().padEnd(5)}  ${e.msg}`);
    },

    async activity() {
        const list = await get('activity', { event: opts.event, limit: opts.limit || 50 });
        if (opts.json) return print(list);
        for (const l of list)
            console.log(`${local(l.timestamp)}  ${l.event.padEnd(20)} ${[l.user, l.keyName, l.ip, l.detail].filter(Boolean).join(' · ')}`);
    },

    async devices() { print(await get('devices')); },

    async 'device-logs'() {
        const list = await get('device-logs', { device: opts.device, screen: opts.screen, entries: opts.entries || 3 });
        if (opts.json) return print(list);
        if (!list.length) return console.log('(no device logs)');
        for (const d of list) {
            console.log(`\n=== ${d.deviceId}  (${d.keyName || 'no key'})`);
            for (const e of d.entries) console.log(`--- ${local(e.at)}\n${e.text.trimEnd()}`);
        }
    },

    async screens()  { print(await get('screens')); },
    async settings() { print(await get('settings')); },
    async updates()  { print(await get('updates')); },

    async get() {
        if (!args[0]) fail('Usage: get <path under /api/debug/>, e.g. get overview');
        const [p, q] = args[0].split('?');
        print(await get(p, Object.fromEntries(new URLSearchParams(q || ''))));
    },
};

if (!cmd || !COMMANDS[cmd]) {
    console.log(fs.readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n')
        .filter(l => l.startsWith('//')).map(l => l.slice(3)).join('\n'));
    process.exit(cmd ? 1 : 0);
}
if (!BASE || !TOKEN) fail('Set PHOTODOCK_URL and PHOTODOCK_DEBUG_TOKEN (or put them in .photodock-debug.env) — create the token in Settings → Debug access.');
await COMMANDS[cmd]();
