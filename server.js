/* ==========================================================================
   AEGIS local server (Node 18+, no dependencies)

   Runs the dashboard on your own machine. It fetches each threat-intel
   source through the shared data layer (lib/core.js), caches it in memory,
   serves /api/* and the files in public/.

   Run:  node server.js        then open http://localhost:8080
   Config: copy .env.example to .env (all keys optional)
   For the hosted version see worker/index.js (Cloudflare Workers).
   ========================================================================== */

import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  MIN, SOURCE_NAMES, SECURITY_HEADERS, createSources, enrichDshield, resolveIps, pruneGeo, makeRedactor, userAgent,
} from './lib/core.js';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, 'public');
loadDotEnv(path.join(ROOT, '.env'));

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const RADAR_TOKEN = (process.env.RADAR_API_TOKEN || '').trim();
const UA = userAgent((process.env.CONTACT_EMAIL || '').trim());
const redact = makeRedactor(RADAR_TOKEN);

/* ------------------------------------------------------------------ helpers */

function loadDotEnv(file) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch { return; }
  for (const line of text.split(/\r?\n/)) {
    const eq = line.indexOf('=');
    if (eq < 1 || line.trimStart().startsWith('#')) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim().replace(/^(['"])(.*)\1$/, '$2');
    if (/^[A-Z0-9_]+$/.test(key) && !(key in process.env)) process.env[key] = value;
  }
}

/* HTTPS GET via node:https rather than fetch(): some hosts (e.g. ransomware.live) publish
   AAAA records but don't answer on IPv6, and fetch's connection racing still times out.
   We prefer IPv4 and fall back to any address family if the host has no A record. */
function request(url, { headers, timeout, family }, redirects = 3) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers, timeout, family }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirects > 0) {
        res.resume();
        resolve(request(new URL(res.headers.location, url).href, { headers, timeout, family }, redirects - 1));
        return;
      }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, statusText: res.statusMessage, text: Buffer.concat(chunks).toString('utf8') }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error(`Timed out after ${timeout / 1000}s`), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
  });
}

async function getJson(url, { headers = {}, timeout = 45000 } = {}) {
  const opts = { headers: { 'User-Agent': UA, Accept: 'application/json, text/plain, */*', ...headers }, timeout };
  let res;
  try {
    res = await request(url, { ...opts, family: 4 });
  } catch (err) {
    if (!['ENOTFOUND', 'EAI_AGAIN', 'EAI_NODATA'].includes(err.code)) throw new Error(`${new URL(url).host}: ${err.message}`);
    res = await request(url, opts);
  }
  if (res.status < 200 || res.status >= 300) {
    const hint = res.status === 429 ? ' (rate limited — will retry later)' : '';
    throw new Error(`${res.status} ${res.statusText} from ${new URL(url).host}${hint}: ${res.text.slice(0, 160)}`);
  }
  try {
    return JSON.parse(res.text);
  } catch {
    throw new Error(`Non-JSON response from ${new URL(url).host}: ${res.text.slice(0, 120).replace(/\s+/g, ' ')}`);
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ------------------------------------------------------------------ in-memory cache
   Fresh for `ttl`. Concurrent callers share one in-flight request. On failure the
   last good value is served with an error attached; with no good value we back off
   for 2 minutes instead of hammering a rate-limited upstream. */

const cache = new Map();

function cached(key, ttl, loader) {
  let entry = cache.get(key);
  if (!entry) cache.set(key, entry = {});
  const now = Date.now();
  if (entry.value !== undefined && now - entry.at < ttl) return Promise.resolve(entry);
  if (entry.pending) return entry.pending;
  if (entry.value === undefined && entry.errorAt && now - entry.errorAt < 2 * MIN) {
    return Promise.reject(new Error(entry.error));
  }
  entry.pending = loader().then(
    value => {
      Object.assign(entry, { value, at: Date.now(), error: null, errorAt: null, pending: null });
      return entry;
    },
    err => {
      Object.assign(entry, { error: err.message, errorAt: Date.now(), pending: null });
      console.warn(`[${new Date().toISOString()}] ${key}: ${redact(err.message)}`);
      if (entry.value !== undefined) return entry;
      throw err;
    });
  return entry.pending;
}

const SOURCES = createSources({ getJson, cached, sleep, radarToken: RADAR_TOKEN });

/* DShield attacker IPs are geolocated slowly in the background; results fill in on later requests. */
const geo = {};
let geoRunning = false;

function withGeo(data) {
  const { data: enriched, pendingIps } = enrichDshield(data, geo);
  if (pendingIps.length && !geoRunning) {
    geoRunning = true;
    resolveIps(pendingIps, geo, { getJson, sleep })
      .then(() => pruneGeo(geo))
      .catch(err => console.warn('geo lookup failed:', redact(err.message)))
      .finally(() => { geoRunning = false; });
  }
  return enriched;
}

/* ==========================================================================
   Routing
   ========================================================================== */

async function handleApi(name, res) {
  if (name === 'status') {
    const status = {};
    for (const key of SOURCE_NAMES) {
      const e = cache.get(`src:${key}`) || {};
      status[key] = { fetchedAt: e.at ? new Date(e.at).toISOString() : null, error: redact(e.error) || null };
    }
    status.radar.configured = !!RADAR_TOKEN;
    return sendJson(res, 200, status);
  }
  if (!SOURCE_NAMES.includes(name)) return sendJson(res, 404, { error: 'Unknown source' });
  const src = SOURCES[name];
  try {
    const entry = await cached(`src:${name}`, src.ttl, src.load);
    sendJson(res, 200, {
      source: name,
      fetchedAt: new Date(entry.at).toISOString(),
      stale: !!entry.error,
      error: redact(entry.error) || null,
      data: name === 'dshield' ? withGeo(entry.value) : entry.value,
    });
  } catch (err) {
    sendJson(res, 502, { source: name, error: redact(err.message), data: null });
  }
}

function send(res, code, headers, body) {
  res.writeHead(code, { ...SECURITY_HEADERS, ...headers });
  res.end(body);
}

function sendJson(res, code, body) {
  send(res, code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, JSON.stringify(body));
}

const sendText = (res, code, text) => send(res, code, { 'Content-Type': 'text/plain; charset=utf-8' }, text);

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

/* Only public/index.html and files directly under public/css and public/js are served. */
function serveStatic(pathname, res) {
  let rel;
  try {
    rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  } catch {
    return sendText(res, 400, 'Bad request');          // malformed %-encoding
  }
  const allowed = rel === 'index.html' || /^(css|js)\/[\w-]+\.(css|js)$/.test(rel);
  const file = path.join(PUBLIC, rel);
  if (!allowed || !file.startsWith(PUBLIC + path.sep)) return sendText(res, 404, 'Not found');
  fs.readFile(file, (err, buf) => {
    if (err) return sendText(res, 404, 'Not found');
    send(res, 200, { 'Content-Type': MIME[path.extname(file)], 'Cache-Control': 'no-cache' }, buf);
  });
}

/* DNS-rebinding guard: when listening on loopback, only answer requests addressed to loopback names,
   so a malicious web page can't point its own hostname at 127.0.0.1 and read this server. */
const LOOPBACK_HOST = ['127.0.0.1', 'localhost', '::1'].includes(HOST);
const ALLOWED_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);

function hostAllowed(req) {
  if (!LOOPBACK_HOST) return true;
  const host = String(req.headers.host || '').toLowerCase();
  const hostname = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0];
  return ALLOWED_HOSTNAMES.has(hostname);
}

http.createServer((req, res) => {
  try {
    if (!hostAllowed(req)) return sendText(res, 403, 'Forbidden host');
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { Allow: 'GET, HEAD' }, '');
    const { pathname } = new URL(req.url, 'http://localhost');
    if (pathname.startsWith('/api/')) return void handleApi(pathname.slice(5), res);
    serveStatic(pathname, res);
  } catch (err) {
    console.error('request error:', redact(err.message));
    if (!res.headersSent) sendText(res, 500, 'Server error');
  }
}).listen(PORT, HOST, () => {
  console.log(`AEGIS dashboard on http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`Cloudflare Radar: ${RADAR_TOKEN ? 'enabled' : 'disabled (set RADAR_API_TOKEN in .env to enable)'}`);
  // Warm the caches so the first page load has data sooner.
  for (const name of SOURCE_NAMES) cached(`src:${name}`, SOURCES[name].ttl, SOURCES[name].load).catch(() => {});
});
