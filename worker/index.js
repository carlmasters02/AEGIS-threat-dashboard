/* ==========================================================================
   AEGIS on Cloudflare Workers

   scheduled (cron, every 5 min): refreshes each source whose cache has
     expired, using the same data layer as the Node server (lib/core.js), and
     stores ready-to-serve JSON in KV. This is the only code that contacts the
     upstream feeds, so visitor traffic can never exceed their rate limits.

   fetch: /api/<source> is a single KV read; everything else is a static
     asset from public/, returned with the dashboard's security headers.

   Secrets (wrangler secret put): RADAR_API_TOKEN, CONTACT_EMAIL (optional)
   ========================================================================== */

import {
  MIN, SOURCE_NAMES, SECURITY_HEADERS, createSources, enrichDshield, resolveIps, pruneGeo, makeRedactor, userAgent,
} from '../lib/core.js';

const WARMING_UP = 'Collecting data: the first refresh runs within 5 minutes of deployment.';

const sleep = ms => new Promise(r => setTimeout(r, ms));

function makeGetJson(ua) {
  return async function getJson(url, { headers = {}, timeout = 45000 } = {}) {
    const res = await fetch(url, {
      headers: { 'User-Agent': ua, Accept: 'application/json, text/plain, */*', ...headers },
      signal: AbortSignal.timeout(timeout),
    });
    const text = await res.text();
    const host = new URL(url).host;
    if (!res.ok) {
      const hint = res.status === 429 ? ' (rate limited — will retry later)' : '';
      throw new Error(`${res.status} ${res.statusText} from ${host}${hint}: ${text.slice(0, 160)}`);
    }
    try {
      return JSON.parse(text);
    } catch {
      throw new Error(`Non-JSON response from ${host}: ${text.slice(0, 120).replace(/\s+/g, ' ')}`);
    }
  };
}

/* KV-backed version of the Node server's cache, so entries survive between cron runs.
   Fresh for `ttl`; on failure the last good value is kept with the error attached;
   with no good value, retries back off for 2 minutes. */
function makeKvCache(kv, redact) {
  return async function cached(key, ttl, loader) {
    const kvKey = `cache:${key}`;
    const entry = (await kv.get(kvKey, 'json')) || {};
    const now = Date.now();
    if (entry.value !== undefined && now - entry.at < ttl) return entry;
    if (entry.value === undefined && entry.errorAt && now - entry.errorAt < 2 * MIN) throw new Error(entry.error);
    try {
      const fresh = { value: await loader(), at: Date.now(), error: null, errorAt: null };
      await kv.put(kvKey, JSON.stringify(fresh));
      return fresh;
    } catch (err) {
      const failed = { ...entry, error: redact(err.message), errorAt: Date.now() };
      await kv.put(kvKey, JSON.stringify(failed));
      console.error(JSON.stringify({ message: 'source refresh failed', key, error: failed.error }));
      if (failed.value !== undefined) return failed;
      throw err;
    }
  };
}

/* Attach AS countries to DShield's top attacker IPs, looking up any new IPs (gently). */
async function geolocate(kv, data, getJson) {
  const geo = (await kv.get('geo', 'json')) || {};
  const first = enrichDshield(data, geo);
  if (!first.pendingIps.length) return { data: first.data, changed: false };
  await resolveIps(first.pendingIps, geo, { getJson, sleep });
  pruneGeo(geo);
  await kv.put('geo', JSON.stringify(geo));
  return { data: enrichDshield(data, geo).data, changed: true };
}

async function refreshAll(env) {
  const kv = env.DATA;
  const token = (env.RADAR_API_TOKEN || '').trim();
  const redact = makeRedactor(token);
  const getJson = makeGetJson(userAgent((env.CONTACT_EMAIL || '').trim()));
  const cached = makeKvCache(kv, redact);
  const sources = createSources({ getJson, cached, sleep, radarToken: token });

  // Signatures of what was last written, so unchanged payloads aren't rewritten every 5 minutes.
  const sigs = (await kv.get('meta:signatures', 'json')) || {};
  const nextSigs = { ...sigs };
  const status = {};

  const results = await Promise.allSettled(SOURCE_NAMES.map(async name => {
    const entry = await cached(`src:${name}`, sources[name].ttl, sources[name].load);
    if (name !== 'dshield') return { entry, data: entry.value, extra: '' };
    const g = await geolocate(kv, entry.value, getJson);
    return { entry, data: g.data, extra: g.changed ? `geo@${Date.now()}` : sigs.dshieldGeo || '' };
  }));

  const writes = [];
  results.forEach((r, i) => {
    const name = SOURCE_NAMES[i];
    if (r.status === 'fulfilled') {
      const { entry, data, extra } = r.value;
      const error = redact(entry.error) || null;
      status[name] = { fetchedAt: new Date(entry.at).toISOString(), error };
      const sig = `${entry.at}|${error}|${extra}`;
      if (name === 'dshield') nextSigs.dshieldGeo = extra;
      if (sig !== sigs[name]) {
        nextSigs[name] = sig;
        writes.push(kv.put(`api:${name}`, JSON.stringify({
          source: name, fetchedAt: new Date(entry.at).toISOString(), stale: !!entry.error, error, data,
        })));
      }
    } else {
      const error = redact(r.reason?.message || 'Refresh failed');
      status[name] = { fetchedAt: null, error };
      const sig = `error|${error}`;
      if (sig !== sigs[name]) {
        nextSigs[name] = sig;
        // Only reached when the source has never loaded; a stale-but-good payload is never overwritten.
        writes.push(kv.put(`api:${name}`, JSON.stringify({ source: name, error, data: null })));
      }
    }
  });
  status.radar = { ...status.radar, configured: !!token };

  const statusJson = JSON.stringify(status);
  if (statusJson !== sigs.status) {
    nextSigs.status = statusJson;
    writes.push(kv.put('api:status', statusJson));
  }
  await Promise.all(writes);
  if (JSON.stringify(nextSigs) !== JSON.stringify(sigs)) await kv.put('meta:signatures', JSON.stringify(nextSigs));

  console.log(JSON.stringify({ message: 'refresh complete', updated: writes.length, status }));
}

/* ------------------------------------------------------------------ responses */

function withSecurityHeaders(response, url) {
  const res = new Response(response.body, response);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.headers.set(k, v);
  if (url.protocol === 'https:') res.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  return res;
}

function json(status, body, url) {
  return withSecurityHeaders(new Response(typeof body === 'string' ? body : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  }), url);
}

async function handleApi(name, env, url) {
  if (name !== 'status' && !SOURCE_NAMES.includes(name)) return json(404, { error: 'Unknown source' }, url);
  const body = await env.DATA.get(`api:${name}`);
  if (body) return json(200, body, url);
  return json(503, { source: name, error: WARMING_UP, data: null }, url);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (request.method !== 'GET' && request.method !== 'HEAD') {
        return withSecurityHeaders(new Response('Method not allowed', { status: 405, headers: { Allow: 'GET, HEAD' } }), url);
      }
      if (url.pathname.startsWith('/api/')) return await handleApi(url.pathname.slice(5), env, url);
      return withSecurityHeaders(await env.ASSETS.fetch(request), url);
    } catch (err) {
      console.error(JSON.stringify({ message: 'request failed', path: url.pathname, error: makeRedactor(env.RADAR_API_TOKEN)(err.message) }));
      return withSecurityHeaders(new Response('Server error', { status: 500 }), url);
    }
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(refreshAll(env));
  },
};
