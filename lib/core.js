/* ==========================================================================
   AEGIS core — platform-neutral data layer shared by the Node server
   (server.js) and the Cloudflare Worker (worker/index.js).

   Each source is { ttl, load }. The runtime injects:
     getJson(url, { headers, timeout })  -> parsed JSON (throws on HTTP/parse errors)
     cached(key, ttl, loader)            -> { value, at, error } (serves stale on failure)
     sleep(ms)
   ========================================================================== */

export const MIN = 60 * 1000;
export const HOUR = 60 * MIN;
export const DAY = 24 * HOUR;

export const SOURCE_NAMES = ['kev', 'ransomware', 'dshield', 'abusech', 'radar'];

/* ------------------------------------------------------------------ helpers */

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

export function userAgent(contact) {
  return `AEGIS-threat-dashboard/2.0 (personal research dashboard${contact ? `; ${contact}` : ''})`;
}

/* Never let the API token appear in a log line or an HTTP response. */
export function makeRedactor(token) {
  return msg => {
    if (msg == null) return msg;
    const text = String(msg);
    return token ? text.split(token).join('[redacted]') : text;
  };
}

/* Headers on every response. The CSP allows exactly what the page loads:
   our own files, the pinned CDN scripts + map data, and Google Fonts. */
export const SECURITY_HEADERS = {
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

/* ==========================================================================
   Sources
   ========================================================================== */

export function createSources({ getJson, cached, sleep, radarToken }) {
  /* ---------------- CISA Known Exploited Vulnerabilities + FIRST EPSS ---------------- */

  async function loadKev() {
    let kev;
    try {
      kev = await getJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    } catch {
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
      const e = await getJson(`https://api.first.org/data/v1/epss?cve=${recent.map(r => encodeURIComponent(r.cve)).join(',')}`);
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

  /* ---------------- ransomware.live (free API v2 — 1 request/min per endpoint) ---------------- */

  const RL = 'https://api.ransomware.live/v2';
  let rlLastCall = 0;

  /* Space ransomware.live calls out so a cold start never bursts the API. */
  async function rlGet(pathname) {
    const wait = rlLastCall + 3000 - Date.now();
    if (wait > 0) await sleep(wait);
    rlLastCall = Date.now();
    return getJson(`${RL}/${pathname}`);
  }

  /* Keep only the fields we use, so cached months stay small. */
  const trimVictims = list => list.map(v => ({
    victim: v.victim, group: v.group, country: v.country, activity: v.activity, discovered: v.discovered, url: v.url,
  }));

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
      const entry = await cached(`rl:victims:${ym}`, i === 0 ? 30 * MIN : 12 * HOUR,
        async () => trimVictims(await rlGet(`victims/${ym}`)));
      raw.push(...entry.value);
    }

    let press = [];
    let pressError = null;
    try {
      const entry = await cached('rl:press', 2 * HOUR, async () => (await rlGet('recentcyberattacks'))
        .map(p => ({
          date: p.date || p.added,
          added: p.added,
          title: p.title || p.victim || p.name || null,
          group: p.claim_gang || p.group || null,
          country: (p.country || '').toUpperCase() || null,
          url: p.url || p.link || p.claim_url || null,
        }))
        .filter(p => p.title)
        .sort((a, b) => String(b.date).localeCompare(String(a.date)))
        .slice(0, 25));
      press = entry.value;
    } catch (err) {
      pressError = err.message;
    }

    // Normalise + de-duplicate
    const seen = new Set();
    const victims = [];
    for (const v of raw) {
      const t = Date.parse(v.discovered);
      if (!Number.isFinite(t) || t > now + HOUR) continue;
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

  /* ---------------- SANS Internet Storm Center / DShield ---------------- */

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

  /* ---------------- abuse.ch — Feodo Tracker + URLhaus (CC0) ---------------- */

  async function loadFeodo() {
    const rows = await getJson('https://feodotracker.abuse.ch/downloads/ipblocklist.json');
    const online = rows.filter(r => r.status === 'online');
    return {
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
  }

  async function loadUrlhaus() {
    const feed = await getJson('https://urlhaus.abuse.ch/downloads/json_recent/', { timeout: 90000 });
    const now = Date.now();
    const rows = [];
    for (const [id, list] of Object.entries(feed)) {
      for (const r of list) rows.push({ id, ...r, t: Date.parse(r.dateadded.replace(' UTC', 'Z').replace(' ', 'T')) });
    }
    rows.sort((a, b) => b.t - a.t);
    const day = rows.filter(r => now - r.t < DAY);
    const tagCounts = {};
    for (const r of day) for (const tag of r.tags || []) tagCounts[tag] = (tagCounts[tag] || 0) + 1;
    const hourly = new Array(24).fill(0);
    for (const r of day) hourly[23 - Math.floor((now - r.t) / HOUR)]++;
    return {
      total: rows.length,
      added24h: day.length,
      online: rows.filter(r => r.url_status === 'online').length,
      threats: topEntries(countBy(day, r => r.threat), 6),
      tags: topEntries(tagCounts, 10),
      hourly: hourly.map((n, i) => ({ date: new Date(now - (23 - i) * HOUR).toISOString(), value: n })),
      latest: rows.slice(0, 25).map(r => {
        let host;
        try { host = new URL(r.url).host; } catch { host = String(r.url).slice(0, 40); }
        return { id: r.id, added: new Date(r.t).toISOString(), host: defang(host), threat: r.threat,
          tags: r.tags || [], status: r.url_status, link: r.urlhaus_link };
      }),
    };
  }

  async function loadAbuseCh() {
    const [feodo, urlhaus] = await Promise.allSettled([
      cached('abusech:feodo', HOUR, loadFeodo),
      cached('abusech:urlhaus', 15 * MIN, loadUrlhaus),
    ]);
    const out = { feodo: null, urlhaus: null, errors: {} };
    if (feodo.status === 'fulfilled') out.feodo = feodo.value.value;
    else out.errors.feodo = feodo.reason.message;
    if (urlhaus.status === 'fulfilled') out.urlhaus = urlhaus.value.value;
    else out.errors.urlhaus = urlhaus.reason.message;
    if (!out.feodo && !out.urlhaus) throw new Error(Object.values(out.errors).join(' | '));
    return out;
  }

  /* ---------------- Cloudflare Radar (API token "Account > Radar > Read"), CC BY-NC 4.0 ---------------- */

  async function radar(pathq) {
    const sep = pathq.includes('?') ? '&' : '?';
    const j = await getJson(`${RADAR}/${pathq}${sep}format=json`, { headers: { Authorization: `Bearer ${radarToken}` } });
    if (!j.success) throw new Error((j.errors || []).map(e => e.message).join('; ') || 'Radar request failed');
    return j.result;
  }

  async function loadRadar() {
    if (!radarToken) return { configured: false };
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

  return {
    kev:        { ttl: HOUR,     load: loadKev },
    ransomware: { ttl: 30 * MIN, load: loadRansomware },
    dshield:    { ttl: HOUR,     load: loadDshield },
    abusech:    { ttl: 10 * MIN, load: loadAbuseCh },
    radar:      { ttl: 15 * MIN, load: loadRadar },
  };
}

/* ==========================================================================
   DShield attacker geolocation (AS registration country via the ISC IP API)
   `geo` is a plain object { ip: { cc, asname, at } } so it can be kept in
   memory (Node) or serialised to KV (Worker).
   ========================================================================== */

const ISC = 'https://isc.sans.edu/api';

/* Attach AS country to attacker IPs. Returns the IPs that still need a lookup. */
export function enrichDshield(data, geo, now = Date.now()) {
  const pendingIps = [];
  const attackers = data.attackers.map(a => {
    let g = Object.hasOwn(geo, a.ip) ? geo[a.ip] : null;
    if (g && now - g.at > DAY) g = null;       // IP allocations move; re-check daily
    if (!g) pendingIps.push(a.ip);
    return { ...a, cc: g?.cc || null, asname: g?.asname || null };
  });
  const countries = {};
  for (const a of attackers) if (a.cc) countries[a.cc] = (countries[a.cc] || 0) + a.reports;
  return { data: { ...data, attackers, countries, geoPending: pendingIps.length }, pendingIps };
}

/* Look IPs up one at a time (gently — ISC is a volunteer service) and record them in `geo`. */
export async function resolveIps(ips, geo, { getJson, sleep, delayMs = 400 }) {
  for (const ip of ips) {
    try {
      const j = await getJson(`${ISC}/ip/${encodeURIComponent(ip)}?json`, { timeout: 15000 });
      geo[ip] = { cc: j.ip?.ascountry || null, asname: j.ip?.asname || null, at: Date.now() };
    } catch {
      geo[ip] = { cc: null, asname: null, at: Date.now() };
    }
    await sleep(delayMs);
  }
  return geo;
}

/* Drop lookups older than 2 days so the stored map stays small. */
export function pruneGeo(geo, now = Date.now()) {
  for (const ip of Object.keys(geo)) if (now - geo[ip].at > 2 * DAY) delete geo[ip];
  return geo;
}

/* ==========================================================================
   Cloudflare Radar response parsers
   ========================================================================== */

const RADAR = 'https://api.cloudflare.com/client/v4/radar';

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
  .filter(r => Number.isFinite(r.value))
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
  l7Targets:    ['attacks/layer7/top/locations/target?dateRange=1d&limit=40', radarTop],
  l7Origins:    ['attacks/layer7/top/locations/origin?dateRange=1d&limit=40', radarTop],
  l3Targets:    ['attacks/layer3/top/locations/target?dateRange=1d&limit=40', radarTop],
  l3Origins:    ['attacks/layer3/top/locations/origin?dateRange=1d&limit=40', radarTop],
  l7Pairs:      ['attacks/layer7/top/attacks?dateRange=1d&limit=25', radarPairs],
  l3Pairs:      ['attacks/layer3/top/attacks?dateRange=1d&limit=25', radarPairs],
  l3Vectors:    ['attacks/layer3/summary/VECTOR?dateRange=7d', radarSummary],
  l7Rules:      ['attacks/layer7/summary/MANAGED_RULES?dateRange=7d', radarSummary],
  l7Mitigation: ['attacks/layer7/summary/MITIGATION_PRODUCT?dateRange=7d', radarSummary],
  l7Industry:   ['attacks/layer7/summary/INDUSTRY?dateRange=7d', radarSummary],
  l7Series:     ['attacks/layer7/timeseries?dateRange=7d&aggInterval=1h', radarSeries],
  l3Series:     ['attacks/layer3/timeseries?dateRange=7d&aggInterval=1h', radarSeries],
  outages:      ['annotations/outages?dateRange=7d&limit=30', radarOutages],
};
