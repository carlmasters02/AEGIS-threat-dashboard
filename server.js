/* ==========================================================================
   AEGIS data proxy + static server (Node 18+, no dependencies)

   The browser can't call most threat-intel feeds directly (no CORS headers,
   API keys that must stay secret, strict rate limits), so this server:
     - fetches each upstream source on a schedule-friendly TTL cache
     - normalises the responses into small JSON documents under /api/*
     - serves last-known-good data (flagged stale) if an upstream fails
     - serves the dashboard files

   Run:  node server.js        then open http://localhost:8080
   Config: copy .env.example to .env (all keys optional)
   ========================================================================== */

'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = __dirname;
loadDotEnv(path.join(ROOT, '.env'));

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const RADAR_TOKEN = (process.env.CLOUDFLARE_API_TOKEN || '').trim();
const CONTACT = (process.env.CONTACT_EMAIL || '').trim();
const UA = `AEGIS-threat-dashboard/2.0 (personal research dashboard${CONTACT ? `; ${CONTACT}` : ''})`;

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

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
        return resolve(request(new URL(res.headers.location, url).href, { headers, timeout, family }, redirects - 1));
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

async function getText(url, { headers = {}, timeout = 45000 } = {}) {
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
  return res.text;
}

async function getJson(url, opts) {
  const text = await getText(url, opts);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`Non-JSON response from ${new URL(url).host}: ${text.slice(0, 120).replace(/\s+/g, ' ')}`);
  }
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/* Belt and braces: never let the API token appear in a log line or an HTTP response. */
function redact(msg) {
  const text = String(msg ?? '');
  return RADAR_TOKEN ? text.split(RADAR_TOKEN).join('[redacted]') : text;
}

function countBy(items, keyFn) {
  const out = {};
  for (const it of items) {
    const k = keyFn(it);
    if (k != null && k !== '') out[k] = (out[k] || 0) + 1;
  }
  return out;
}

const topEntries = (obj, n) => Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n);
const isoDay = t => new Date(t).toISOString().slice(0, 10);

/* Defang a URL/host so it can't be clicked or auto-linked by accident. */
function defang(s) {
  return String(s).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
}

/* ------------------------------------------------------------------ cache
   Fresh for `ttl`. Concurrent callers share one in-flight request. On failure the
   last good value is served with stale=true; with no good value we back off for
   2 minutes instead of hammering a rate-limited upstream. */

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

/* ==========================================================================
   Source: CISA Known Exploited Vulnerabilities + FIRST EPSS scores
   ========================================================================== */

async function loadKev() {
  let kev;
  try {
    kev = await getJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
  } catch (err) {
    // Official GitHub mirror of the same catalogue
    kev = await getJson('https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json');
  }
  const now = Date.now();
  const ageDays = d => (now - Date.parse(`${d}T00:00:00Z`)) / DAY;
  const vulns = [...kev.vulnerabilities].sort((a, b) =>
    b.dateAdded.localeCompare(a.dateAdded) || b.cveID.localeCompare(a.cveID));

  const recent = vulns.slice(0, 30).map(v => ({
    cve: v.cveID,
    vendor: v.vendorProject,
    product: v.product,
    name: v.vulnerabilityName,
    description: v.shortDescription,
    dateAdded: v.dateAdded,
    dueDate: v.dueDate,
    ransomware: v.knownRansomwareCampaignUse === 'Known',
    epss: null,
  }));

  let epssError = null;
  try {
    const e = await getJson(`https://api.first.org/data/v1/epss?cve=${recent.map(r => r.cve).join(',')}`);
    const byCve = Object.fromEntries(e.data.map(row => [row.cve, { score: +row.epss, percentile: +row.percentile, date: row.date }]));
    for (const r of recent) r.epss = byCve[r.cve] || null;
  } catch (err) {
    epssError = err.message;
  }

  return {
    catalogVersion: kev.catalogVersion,
    released: kev.dateReleased,
    total: kev.count,
    added7: vulns.filter(v => ageDays(v.dateAdded) < 7).length,
    added30: vulns.filter(v => ageDays(v.dateAdded) < 30).length,
    ransomwareKnown: vulns.filter(v => v.knownRansomwareCampaignUse === 'Known').length,
    vendors90: topEntries(countBy(vulns.filter(v => ageDays(v.dateAdded) < 90), v => v.vendorProject), 10),
    recent,
    epssError,
  };
}

/* ==========================================================================
   Source: ransomware.live (free API v2 — personal use, 1 request/min per endpoint)
   Victims posted on ransomware leak sites, with group, country and sector.
   ========================================================================== */

const RL = 'https://api.ransomware.live/v2';
let rlLastCall = 0;

/* Space ransomware.live calls out so a cold start never bursts the API. */
async function rlGet(pathname) {
  const wait = rlLastCall + 3000 - Date.now();
  if (wait > 0) await sleep(wait);
  rlLastCall = Date.now();
  return getJson(`${RL}/${pathname}`);
}

async function loadRansomware() {
  const now = Date.now();
  const d = new Date(now);
  const months = [0, 1, 2].map(i => {
    const m = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - i, 1));
    return `${m.getUTCFullYear()}/${String(m.getUTCMonth() + 1).padStart(2, '0')}`;
  });

  const raw = [];
  for (const [i, ym] of months.entries()) {
    // Past months barely change; refresh them far less often than the current one.
    const entry = await cached(`rl:victims:${ym}`, i === 0 ? 30 * MIN : 12 * HOUR, () => rlGet(`victims/${ym}`));
    raw.push(...entry.value);
  }

  let press = [];
  let pressError = null;
  try {
    const entry = await cached('rl:press', 2 * HOUR, () => rlGet('recentcyberattacks'));
    press = entry.value
      .map(p => ({
        date: p.date || p.added,
        added: p.added,
        title: p.title || p.victim || p.name || null,
        summary: p.summary || p.description || null,
        group: p.claim_gang || p.group || null,
        country: (p.country || '').toUpperCase() || null,
        url: p.url || p.link || p.claim_url || null,
      }))
      .filter(p => p.title)
      .sort((a, b) => String(b.date).localeCompare(String(a.date)))
      .slice(0, 25);
  } catch (err) {
    pressError = err.message;
  }

  // Normalise + de-duplicate
  const seen = new Set();
  const victims = [];
  for (const v of raw) {
    const t = Date.parse(v.discovered);
    if (!isFinite(t) || t > now + HOUR) continue;
    const key = `${v.group}|${v.victim}`;
    if (seen.has(key)) continue;
    seen.add(key);
    victims.push({
      victim: v.victim,
      group: v.group,
      country: /^[A-Z]{2}$/i.test(v.country || '') ? v.country.toUpperCase() : null,
      sector: v.activity && !/^(not found|unknown|)$/i.test(v.activity) ? v.activity : null,
      t,
      url: v.url || null,
    });
  }
  victims.sort((a, b) => b.t - a.t);

  const w30 = victims.filter(v => now - v.t < 30 * DAY);
  const p30 = victims.filter(v => now - v.t >= 30 * DAY && now - v.t < 60 * DAY);
  const dayIndex = t => 29 - Math.floor((now - t) / DAY);

  const priorByGroup = countBy(p30, v => v.group);
  const groupMap = {};
  for (const v of w30) {
    const g = groupMap[v.group] || (groupMap[v.group] = { name: v.group, count: 0, daily: new Array(30).fill(0), countries: {}, sectors: {} });
    g.count++;
    const di = dayIndex(v.t);
    if (di >= 0 && di < 30) g.daily[di]++;
    if (v.country) g.countries[v.country] = (g.countries[v.country] || 0) + 1;
    if (v.sector) g.sectors[v.sector] = (g.sectors[v.sector] || 0) + 1;
  }
  const groups = Object.values(groupMap)
    .sort((a, b) => b.count - a.count)
    .slice(0, 25)
    .map(g => ({
      name: g.name,
      count: g.count,
      prior: priorByGroup[g.name] || 0,
      daily: g.daily,
      countries: g.countries,
      topCountry: topEntries(g.countries, 1)[0]?.[0] || null,
      topSector: topEntries(g.sectors, 1)[0]?.[0] || null,
    }));

  const daily = new Array(30).fill(0);
  for (const v of w30) {
    const di = dayIndex(v.t);
    if (di >= 0 && di < 30) daily[di]++;
  }

  return {
    windowDays: 30,
    total30: w30.length,
    prior30: p30.length,
    last24h: victims.filter(v => now - v.t < DAY).length,
    last7d: victims.filter(v => now - v.t < 7 * DAY).length,
    prior7d: victims.filter(v => now - v.t >= 7 * DAY && now - v.t < 14 * DAY).length,
    groupsActive30: Object.keys(groupMap).length,
    groups,
    countries: countBy(w30, v => v.country),
    sectors: topEntries(countBy(w30, v => v.sector), 12),
    daily: daily.map((n, i) => ({ date: isoDay(now - (29 - i) * DAY), value: n })),
    latest: victims.slice(0, 40).map(v => ({ ...v, discovered: new Date(v.t).toISOString() })),
    press,
    pressError,
  };
}

/* ==========================================================================
   Source: SANS Internet Storm Center / DShield (distributed sensor network)
   ========================================================================== */

const ISC = 'https://isc.sans.edu/api';
const ipGeo = new Map();          // ip -> { cc, asname, at }
let geoRunning = false;

async function loadDshield() {
  const end = new Date(Date.now() - DAY);
  const start = new Date(Date.now() - 31 * DAY);
  const [infocon, daily, ports, topips] = await Promise.all([
    getJson(`${ISC}/infocon?json`),
    getJson(`${ISC}/dailysummary/${isoDay(start)}/${isoDay(end)}?json`),
    getJson(`${ISC}/topports/records/12?json`),
    getJson(`${ISC}/topips/records/40?json`),
  ]);
  const asList = x => (Array.isArray(x) ? x : Object.values(x)).filter(r => r && typeof r === 'object');
  return {
    infocon: infocon.status,
    daily: asList(daily).map(r => ({ date: r.date, records: +r.records, sources: +r.sources, targets: +r.targets })),
    ports: asList(ports).filter(r => r.targetport != null).map(r => ({
      port: +r.targetport, records: +r.records, targets: +r.targets, sources: +r.sources })),
    attackers: asList(topips).filter(r => r.source).map(r => ({ ip: r.source, reports: +r.reports, targets: +r.targets })),
  };
}

/* Attach AS country to attacker IPs; unknown IPs are looked up slowly in the background. */
function enrichDshield(data) {
  const pending = [];
  const attackers = data.attackers.map(a => {
    let g = ipGeo.get(a.ip);
    if (g && Date.now() - g.at > DAY) g = null;       // IP allocations move; re-check daily
    if (!g) pending.push(a.ip);
    return { ...a, cc: g?.cc || null, asname: g?.asname || null };
  });
  if (pending.length && !geoRunning) resolveIps(pending);
  const countries = {};
  for (const a of attackers) if (a.cc) countries[a.cc] = (countries[a.cc] || 0) + a.reports;
  return { ...data, attackers, countries, geoPending: pending.length };
}

async function resolveIps(ips) {
  geoRunning = true;
  if (ipGeo.size > 5000) ipGeo.clear();
  try {
    for (const ip of ips) {
      try {
        const j = await getJson(`${ISC}/ip/${encodeURIComponent(ip)}?json`, { timeout: 15000 });
        ipGeo.set(ip, { cc: j.ip?.ascountry || null, asname: j.ip?.asname || null, at: Date.now() });
      } catch {
        ipGeo.set(ip, { cc: null, asname: null, at: Date.now() });
      }
      await sleep(400);   // be gentle with the ISC API
    }
  } finally {
    geoRunning = false;
  }
}

/* ==========================================================================
   Source: abuse.ch — Feodo Tracker (botnet C2s) + URLhaus (malware URLs), CC0
   ========================================================================== */

async function loadAbuseCh() {
  const [feodo, urlhaus] = await Promise.allSettled([
    cached('abusech:feodo', HOUR, () => getJson('https://feodotracker.abuse.ch/downloads/ipblocklist.json')),
    cached('abusech:urlhaus', 15 * MIN, () => getJson('https://urlhaus.abuse.ch/downloads/json_recent/', { timeout: 90000 })),
  ]);
  const out = { feodo: null, urlhaus: null, errors: {} };

  if (feodo.status === 'fulfilled') {
    const rows = feodo.value.value;
    const online = rows.filter(r => r.status === 'online');
    out.feodo = {
      total: rows.length,
      online: online.length,
      byCountry: countBy(rows, r => r.country),
      onlineByCountry: countBy(online, r => r.country),
      byMalware: topEntries(countBy(rows, r => r.malware), 8),
      servers: rows
        .sort((a, b) => String(b.last_online).localeCompare(String(a.last_online)))
        .slice(0, 30)
        .map(r => ({ ip: r.ip_address, port: r.port, status: r.status, country: r.country, malware: r.malware,
          asname: r.as_name, firstSeen: r.first_seen, lastOnline: r.last_online })),
    };
  } else out.errors.feodo = feodo.reason.message;

  if (urlhaus.status === 'fulfilled') {
    const now = Date.now();
    const rows = [];
    for (const [id, list] of Object.entries(urlhaus.value.value)) {
      for (const r of list) rows.push({ id, ...r, t: Date.parse(r.dateadded.replace(' UTC', 'Z').replace(' ', 'T')) });
    }
    rows.sort((a, b) => b.t - a.t);
    const day = rows.filter(r => now - r.t < DAY);
    const tagCounts = {};
    for (const r of day) for (const tag of r.tags || []) tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    const hourly = new Array(24).fill(0);
    for (const r of day) hourly[23 - Math.floor((now - r.t) / HOUR)]++;
    out.urlhaus = {
      total: rows.length,
      added24h: day.length,
      online: rows.filter(r => r.url_status === 'online').length,
      threats: topEntries(countBy(day, r => r.threat), 6),
      tags: topEntries(tagCounts, 10),
      hourly: hourly.map((n, i) => ({ date: new Date(now - (23 - i) * HOUR).toISOString(), value: n })),
      latest: rows.slice(0, 25).map(r => {
        let host = '';
        try { host = new URL(r.url).host; } catch { host = r.url.slice(0, 40); }
        return { id: r.id, added: new Date(r.t).toISOString(), host: defang(host), threat: r.threat,
          tags: r.tags || [], status: r.url_status, link: r.urlhaus_link };
      }),
    };
  } else out.errors.urlhaus = urlhaus.reason.message;

  if (!out.feodo && !out.urlhaus) throw new Error(Object.values(out.errors).join(' | '));
  return out;
}

/* ==========================================================================
   Source: Cloudflare Radar (free API token, "Account > Radar > Read"), CC BY-NC 4.0
   ========================================================================== */

const RADAR = 'https://api.cloudflare.com/client/v4/radar';

async function radar(pathq) {
  const sep = pathq.includes('?') ? '&' : '?';
  const j = await getJson(`${RADAR}/${pathq}${sep}format=json`, { headers: { Authorization: `Bearer ${RADAR_TOKEN}` } });
  if (!j.success) throw new Error((j.errors || []).map(e => e.message).join('; ') || 'Radar request failed');
  return j.result;
}

const radarTop = result => (result.top_0 || []).map(r => ({
  cc: r.targetCountryAlpha2 || r.originCountryAlpha2 || r.clientCountryAlpha2,
  name: r.targetCountryName || r.originCountryName || r.clientCountryName,
  value: +r.value,
})).filter(r => r.cc);

const radarPairs = result => (result.top_0 || []).map(r => ({
  from: r.originCountryAlpha2, fromName: r.originCountryName,
  to: r.targetCountryAlpha2, toName: r.targetCountryName,
  value: +r.value,
})).filter(r => r.from && r.to);

const radarSummary = result => Object.entries(result.summary_0 || {})
  .map(([label, value]) => ({ label, value: +value }))
  .filter(r => isFinite(r.value))
  .sort((a, b) => b.value - a.value);

function radarSeries(result) {
  const key = Object.keys(result).find(k => k.startsWith('serie'));
  const s = key ? result[key] : null;
  return {
    normalization: result.meta?.normalization || null,
    points: s ? s.timestamps.map((t, i) => ({ date: t, value: +s.values[i] })) : [],
  };
}

const radarOutages = result => (result.annotations || []).map(a => ({
  id: a.id,
  start: a.startDate,
  end: a.endDate || null,
  description: a.description,
  scope: a.scope || null,
  locations: (a.locationsDetails || []).map(l => ({ cc: l.code, name: l.name })),
  asns: (a.asnsDetails || []).map(x => x.name).filter(Boolean),
  cause: a.outage?.outageCause || null,
  type: a.outage?.outageType || null,
  url: a.linkedUrl || null,
}));

const RADAR_PARTS = {
  l7Targets:   ['attacks/layer7/top/locations/target?dateRange=1d&limit=40', radarTop],
  l7Origins:   ['attacks/layer7/top/locations/origin?dateRange=1d&limit=40', radarTop],
  l3Targets:   ['attacks/layer3/top/locations/target?dateRange=1d&limit=40', radarTop],
  l3Origins:   ['attacks/layer3/top/locations/origin?dateRange=1d&limit=40', radarTop],
  l7Pairs:     ['attacks/layer7/top/attacks?dateRange=1d&limit=25', radarPairs],
  l3Pairs:     ['attacks/layer3/top/attacks?dateRange=1d&limit=25', radarPairs],
  l3Vectors:   ['attacks/layer3/summary/VECTOR?dateRange=7d', radarSummary],
  l7Rules:     ['attacks/layer7/summary/MANAGED_RULES?dateRange=7d', radarSummary],
  l7Mitigation:['attacks/layer7/summary/MITIGATION_PRODUCT?dateRange=7d', radarSummary],
  l7Industry:  ['attacks/layer7/summary/INDUSTRY?dateRange=7d', radarSummary],
  l7Series:    ['attacks/layer7/timeseries?dateRange=7d&aggInterval=1h', radarSeries],
  l3Series:    ['attacks/layer3/timeseries?dateRange=7d&aggInterval=1h', radarSeries],
  outages:     ['annotations/outages?dateRange=7d&limit=30', radarOutages],
};

async function loadRadar() {
  if (!RADAR_TOKEN) return { configured: false };
  const names = Object.keys(RADAR_PARTS);
  const settled = await Promise.allSettled(names.map(n => radar(RADAR_PARTS[n][0])));
  const parts = {};
  const errors = {};
  settled.forEach((s, i) => {
    const n = names[i];
    if (s.status === 'fulfilled') {
      try { parts[n] = RADAR_PARTS[n][1](s.value); } catch (err) { errors[n] = `parse: ${err.message}`; }
    } else errors[n] = s.reason.message;
  });
  if (!Object.keys(parts).length) throw new Error(Object.values(errors)[0] || 'All Radar requests failed');
  return { configured: true, parts, errors };
}

/* ==========================================================================
   Routing
   ========================================================================== */

const SOURCES = {
  kev:        { ttl: HOUR,      load: loadKev },
  ransomware: { ttl: 30 * MIN,  load: loadRansomware },
  dshield:    { ttl: HOUR,      load: loadDshield, enrich: enrichDshield },
  abusech:    { ttl: 10 * MIN,  load: loadAbuseCh },
  radar:      { ttl: 15 * MIN,  load: loadRadar },
};

async function handleApi(name, res) {
  if (name === 'status') {
    const status = {};
    for (const key of Object.keys(SOURCES)) {
      const e = cache.get(`src:${key}`) || {};
      status[key] = { fetchedAt: e.at ? new Date(e.at).toISOString() : null, error: e.error ? redact(e.error) : null };
    }
    status.radar.configured = !!RADAR_TOKEN;
    return sendJson(res, 200, status);
  }
  if (!Object.hasOwn(SOURCES, name)) return sendJson(res, 404, { error: 'Unknown source' });
  const src = SOURCES[name];
  try {
    const entry = await cached(`src:${name}`, src.ttl, src.load);
    const data = src.enrich ? src.enrich(entry.value) : entry.value;
    sendJson(res, 200, {
      source: name,
      fetchedAt: new Date(entry.at).toISOString(),
      stale: !!entry.error,
      error: entry.error ? redact(entry.error) : null,
      data,
    });
  } catch (err) {
    sendJson(res, 502, { source: name, error: redact(err.message), data: null });
  }
}

/* Headers on every response. The CSP allows exactly what the page loads:
   our own files, the pinned CDN scripts + map data, and Google Fonts. */
const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Content-Security-Policy': [
    "default-src 'none'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "connect-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data: blob:",
    "worker-src 'self' blob:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; '),
};

function send(res, code, headers, body) {
  res.writeHead(code, { ...SECURITY_HEADERS, ...headers });
  res.end(body);
}

function sendJson(res, code, body) {
  send(res, code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, JSON.stringify(body));
}

const sendText = (res, code, text) => send(res, code, { 'Content-Type': 'text/plain; charset=utf-8' }, text);

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

/* Only index.html and files directly under css/ and js/ are served — never .env or server code. */
function serveStatic(pathname, res) {
  let rel;
  try {
    rel = pathname === '/' ? 'index.html' : decodeURIComponent(pathname).replace(/^\/+/, '');
  } catch {
    return sendText(res, 400, 'Bad request');          // malformed %-encoding
  }
  const allowed = rel === 'index.html' || /^(css|js)\/[\w-]+\.(css|js)$/.test(rel);
  const file = path.join(ROOT, rel);
  if (!allowed || !file.startsWith(ROOT + path.sep)) return sendText(res, 404, 'Not found');
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
  console.log(`Cloudflare Radar: ${RADAR_TOKEN ? 'enabled' : 'disabled (set CLOUDFLARE_API_TOKEN in .env to enable)'}`);
  // Warm the caches so the first page load has data sooner.
  for (const [name, src] of Object.entries(SOURCES)) cached(`src:${name}`, src.ttl, src.load).catch(() => {});
});
