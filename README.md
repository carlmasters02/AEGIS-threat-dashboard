# AEGIS — Global Cyber Threat Operations Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-a100ff.svg)](LICENSE)
![Node 18+](https://img.shields.io/badge/node-%3E%3D18-3ddc97.svg)
![Runtime dependencies: none](https://img.shields.io/badge/runtime%20dependencies-none-3ee6ff.svg)
![Cloudflare Workers](https://img.shields.io/badge/deploys%20to-Cloudflare%20Workers-f38020.svg)

A SOC-style dashboard with a 3D threat heatmap globe and live intel panels, built entirely on
**real, public threat-intelligence feeds**. Nothing is simulated: if a source is unavailable,
its panels say so instead of inventing numbers.

It runs two ways from the same code:

- **Locally** with `node server.js`: no install, good for development.
- **Hosted** on Cloudflare Workers: always on, custom domain, and a scheduled job that shields
  the upstream APIs from visitor traffic.

## Features

- **3D heatmap globe:** five switchable country layers (HTTP attack targets and origins, DDoS
  targets, ransomware victims, scanner origins), animated cross-border attack corridors, and
  markers on countries hosting botnet C2 servers. Hover a country for a summary; click it for a detailed card.
- **Ransomware group leaderboard:** victims claimed per group over 30 days, with a daily sparkline
  and the change against the previous 30 days. Click a group to map its victims on the globe.
- **Threat intel alerts:** newly exploited CVEs, press-reported attacks, leak-site posts, internet
  outages and online botnet C2s, merged into one severity-rated feed you can filter.
- **Panels:** attack vectors, most-targeted countries, activity trends, known exploited
  vulnerabilities with EPSS scores, KPI strip, SANS Infocon gauge and a scrolling intel ticker.
- **Source transparency:** the **Sources** button shows each feed's status, last update and license.

## Run locally

Requires [Node.js](https://nodejs.org/) 18 or newer. There are no packages to install.

```bash
git clone https://github.com/carlmasters02/AEGIS-threat-dashboard.git
cd AEGIS-threat-dashboard
cp .env.example .env      # optional: add keys (see Configuration)
node server.js            # or: npm start
```

Then open **http://localhost:8080**.

The page must be opened through a server, not as a `file://`. Most feeds block direct browser
requests, and some need keys that must stay private, so the server fetches, caches and normalises
every source. Four of the five sources work with no configuration.

## Configuration

| Variable | Purpose | Local (`.env`) | Hosted (Worker) |
|---|---|---|---|
| `RADAR_API_TOKEN` | Enables Cloudflare Radar (see below) | ✓ | `wrangler secret put` |
| `CONTACT_EMAIL` | Sent in the User-Agent to SANS ISC, which asks API users to identify themselves | ✓ | `wrangler secret put` |
| `HOST` / `PORT` | Where the local server listens (default `127.0.0.1:8080`) | ✓ | — |

Everything is optional. The local server reads `.env` only at startup, so **restart it after
editing `.env`**.

> The token variable is deliberately **not** called `CLOUDFLARE_API_TOKEN`. Wrangler treats that
> name as its own login and would try to deploy with your read-only Radar token.

### Getting a Cloudflare Radar token (free, recommended)

Radar is the only free source with **country-to-country attack flows**. Without it the globe has
no attack corridors, and the Radar heat layers, vectors and trends are disabled.

1. Create a free Cloudflare account and open https://dash.cloudflare.com/profile/api-tokens.
2. Choose **Create Token** › **Custom token**.
3. Under **Permissions**, choose **Account › Radar › Read**.
4. Under **Account Resources**, choose **Include** and select your account.
5. Create the token and put it in `.env` as `RADAR_API_TOKEN=...` (no quotes).

Use an **API Token**, not the Global API Key.

## Deploy to Cloudflare Workers

**How it works.** A cron trigger runs every 5 minutes, refreshes each source whose cache has
expired, and stores ready-to-serve JSON in Workers KV. Visitor requests to `/api/*` are a single
KV read and never reach the upstream feeds, so traffic spikes can't break any provider's rate
limits. The dashboard files in `public/` are served as static assets with the same security headers.

**Plan.** The **Workers Paid plan ($5/month)** is required. On the free plan a run gets only 10 ms
of CPU time and 50 outbound requests. Parsing the URLhaus feed alone exceeds that CPU limit, and a
full refresh makes about 60 requests.

```bash
npm install                                   # installs Wrangler (deploy tool only)
npx wrangler login                            # one-time browser login
npx wrangler secret put RADAR_API_TOKEN       # paste the token when prompted
npx wrangler secret put CONTACT_EMAIL         # optional
npx wrangler deploy                           # or: npm run deploy
```

The first deploy creates the KV namespace automatically and prints a `*.workers.dev` URL. Data
appears within **5 minutes**, after the first cron run. Until then the panels say
"Collecting data". Follow the logs with `npx wrangler tail`.

### Custom domain

1. Add your domain to Cloudflare. The easiest way is buying it through
   [Cloudflare Registrar](https://www.cloudflare.com/products/registrar/) (sold at cost); a
   domain bought elsewhere works too, once you point its nameservers at Cloudflare.
2. In `wrangler.jsonc`, uncomment the `routes` line and set your domain:
   ```jsonc
   "routes": [{ "pattern": "yourdomain.com", "custom_domain": true }]
   ```
3. Run `npx wrangler deploy` again. Cloudflare creates the DNS record and TLS certificate.

### Testing the Worker locally

```bash
npm run dev                                   # wrangler dev with local KV, reads .env
curl "http://localhost:8787/__scheduled?cron=*/5+*+*+*+*"   # run the refresh job once
```

## Data sources

| Feature | Source | Data window | Cache |
|---|---|---|---|
| Threat level gauge | [SANS ISC Infocon](https://isc.sans.edu/infocon.html) | current | 1 h |
| Big counter, "DShield reports" KPI, probed ports | [SANS ISC DShield](https://isc.sans.edu/api/) firewall/honeypot logs from volunteer sensors | previous day | 1 h |
| Globe: L7 targets, L7 origins, DDoS targets | [Cloudflare Radar](https://radar.cloudflare.com/security) attack share by country | 24 h | 15 min |
| Globe: attack corridors | Radar top origin → target pairs (share of HTTP attacks) | 24 h | 15 min |
| Globe: Ransomware layer, leaderboard, sectors | [ransomware.live](https://www.ransomware.live) leak-site victims | 30 days | 30 min |
| Globe: Scanners layer | DShield top 40 attacking IPs, grouped by the IP's network registration country | latest day | 1 h |
| Globe: cyan rings | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) botnet C2 servers by country | current | 1 h |
| Event stream, malware URL KPI | [abuse.ch URLhaus](https://urlhaus.abuse.ch/) malware URLs (shown defanged) | 24 h / 30 days | 15 min |
| Known exploited vulnerabilities | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) + [FIRST EPSS](https://www.first.org/epss/) exploit probability | catalog | 1 h |
| Internet outages (KPI + alerts) | Radar outage annotations | 7 days | 15 min |
| Attack vectors | Radar DDoS vectors, web attack types, mitigation products, industries · DShield ports · ransomware sectors · URLhaus tags | per dataset | per source |
| Activity trend | Radar L7 & L3 volume (hourly, 7 d) · ransomware victims/day · DShield reports/day · URLhaus URLs/hour | per dataset | per source |
| Most targeted | Mirrors the selected globe layer | — | — |

The cache column is how often each upstream API is contacted, both locally and on Workers
(where the cron job checks every 5 minutes). The browser polls for updates every 5–30 minutes.

### Alert severity

Feeds don't share a severity scale, so the dashboard applies a transparent triage rule
(`buildAlerts()` in `public/js/main.js`):

- **Critical:** a KEV entry with known ransomware use, or EPSS ≥ 95th percentile
- **High:** any other KEV addition (last 30 days), a press-reported attack, or a nationwide internet outage
- **Medium:** a ransomware leak-site post, or a regional outage
- **Low:** an online botnet C2 server

Alerts are ordered newest day first, most severe first within each day.

## Project layout

```
public/            the dashboard (the only files ever served to browsers)
  index.html
  css/styles.css
  js/data.js       reference data only (ISO country table, source attributions, port names)
  js/api.js        polls /api/* and keeps the last good data per source
  js/globe.js      globe.gl heatmap, corridors and C2 markers
  js/panels.js     renderers for each panel
  js/main.js       maps source data onto the views
lib/core.js        shared data layer: fetch + normalise each source, security headers
server.js          local Node server (in-memory cache)
worker/index.js    Cloudflare Worker (cron refresh into KV, API + static assets)
wrangler.jsonc     Worker configuration
```

Both runtimes expose `/api/kev`, `/api/ransomware`, `/api/dshield`, `/api/abusech`, `/api/radar`
and `/api/status`. Each API response includes `fetchedAt`, and a `stale` flag when an upstream
failed and the last good data is being served. `window.AEGIS` exposes the data store and globe in
the browser DevTools console for experimentation.

## Security

- **Secrets:** the Radar token lives only in `.env` locally, or as an encrypted Worker secret when
  hosted. Neither is committed (`.gitignore` covers `.env` and `.dev.vars`). The token is sent only
  to `api.cloudflare.com`, redacted from all logs and error messages, and never reaches the browser.
- **Files served:** only the contents of `public/`. Server code, config, dotfiles, path traversal
  and malformed URLs are rejected.
- **Upstream protection (Workers):** visitors only ever read KV; only the cron job contacts upstream
  APIs.
- **Local server:** binds to `127.0.0.1` and refuses requests addressed to other hostnames
  (a guard against DNS rebinding).
- **Untrusted feed content:** all feed text is HTML-escaped, links are restricted to `http(s)`,
  and malicious URLs and IPs are defanged (`hxxp`, `[.]`).
- **Security headers:** a strict Content-Security-Policy, plus `X-Frame-Options`,
  `Referrer-Policy`, `nosniff`, and HSTS when served over HTTPS. Every CDN script and the map data
  are pinned with Subresource Integrity hashes.

Found a security issue? Please open a GitHub issue without exploit details, or contact the
maintainer through GitHub.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Banner: "Page opened as a file" | Run `node server.js` and open http://localhost:8080 |
| `EADDRINUSE` on start | Another copy is already running: `pkill -f "node server.js"`, or set a different `PORT` |
| Radar shows "needs a token" | Set `RADAR_API_TOKEN` (not `CLOUDFLARE_API_TOKEN`), then restart or redeploy |
| Hosted panels say "Collecting data" | Normal for up to 5 minutes after the first deploy; check `npx wrangler tail` |
| Wrangler: "Failed to retrieve account IDs" | A `CLOUDFLARE_API_TOKEN` in your environment or `.env` is overriding your login; remove or rename it |
| "Scanners" greyed out right after starting locally | Normal for about 30 s while attacker IPs are geolocated |
| A source shows "rate limited" | ransomware.live allows 1 request/min per endpoint; the cache retries automatically |

## Usage terms and etiquette

The **code** is MIT-licensed, but each **data source** has its own terms, and several are
**non-commercial**:

- **ransomware.live:** the free API is for personal, non-commercial use and allows 1 request/min
  per endpoint. For a public deployment, get their free **PRO API key**, which is licensed for broader use.
- **SANS ISC / DShield:** CC BY-NC-SA. Set `CONTACT_EMAIL` so they can reach you if your usage causes problems.
- **Cloudflare Radar:** CC BY-NC 4.0.
- **abuse.ch (URLhaus, Feodo Tracker):** CC0.
- **CISA KEV:** U.S. Government work. **FIRST EPSS:** free to use with attribution.

A free public dashboard with attribution (see the Sources dialog) fits these terms. Running ads or
charging for access would not, without checking with each provider.

## Known limits

- There is no free, global, per-event "live attack" feed. Commercial threat maps use their own
  sensor networks. The arcs here are Cloudflare's real aggregate attack corridors, not individual attacks.
- The Scanners layer uses the attacking IP's **network registration country** (from ISC),
  which is not always where the machine physically is. Cloud providers often register addresses
  in their home country.
- The ransomware.live free API may lag its PRO API by a few hours.
- Leak-site posts are the attackers' own claims, as collected by ransomware.live. Not every claim is verified.

## Credits

- [globe.gl](https://github.com/vasturiano/globe.gl) / three-globe (MIT) and [three.js](https://threejs.org/) (MIT) for the 3D globe
- [world-atlas](https://github.com/topojson/world-atlas) (ISC; Natural Earth data, public domain) and
  [topojson-client](https://github.com/topojson/topojson-client) (ISC) for country shapes
- Country reference table in `public/js/data.js` derived from [mledoze/countries](https://github.com/mledoze/countries),
  licensed under the [Open Database License (ODbL) 1.0](https://opendatacommons.org/licenses/odbl/1.0/)
- Fonts: Rajdhani, Inter and JetBrains Mono via Google Fonts (SIL Open Font License)
- Threat data from the providers listed in [Data sources](#data-sources)

## License

The code is released under the [MIT License](LICENSE): you are free to use, modify and distribute it,
including commercially, as long as the copyright notice is kept. The MIT license covers this
repository's code only. It does not cover the threat data, which remains under each provider's
terms (see [Usage terms](#usage-terms-and-etiquette)), or the country table, which is ODbL 1.0.
