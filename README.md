# AEGIS — Global Cyber Threat Operations Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-a100ff.svg)](LICENSE)
![Node 18+](https://img.shields.io/badge/node-%3E%3D18-3ddc97.svg)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-3ee6ff.svg)

A SOC-style dashboard with a 3D threat heatmap globe and live intel panels, built entirely on
**real, public threat-intelligence feeds**. Nothing is simulated: if a source is unavailable,
its panels say so instead of inventing numbers.

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

## Quick start

Requires [Node.js](https://nodejs.org/) 18 or newer. There are no packages to install.

```bash
git clone https://github.com/carlmasters02/AEGIS-threat-dashboard.git
cd AEGIS-threat-dashboard
cp .env.example .env      # optional: add keys (see Configuration)
node server.js            # or: npm start
```

Then open **http://localhost:8080**.

The page must be opened through the server, not as a `file://`. Most feeds block direct browser
requests, and some need keys that must stay private, so `server.js` fetches, caches and
normalises every source. Four of the five sources work with no configuration.

## Configuration

All settings go in `.env` (see `.env.example`). Every setting is optional.

| Variable | Purpose | Default |
|---|---|---|
| `CLOUDFLARE_API_TOKEN` | Enables Cloudflare Radar (see below) | unset: Radar panels show "needs a token" |
| `CONTACT_EMAIL` | Sent in the User-Agent to SANS ISC, which asks API users to identify themselves | unset |
| `HOST` | Interface to listen on | `127.0.0.1` |
| `PORT` | Port to listen on | `8080` |

The server reads `.env` only at startup, so **restart it after editing `.env`**.

### Enabling Cloudflare Radar (recommended)

Radar is the only free source with **country-to-country attack flows**. Without it the globe has
no attack corridors, and the Radar heat layers, vectors and trends are disabled.

1. Create a free Cloudflare account and open https://dash.cloudflare.com/profile/api-tokens.
2. Choose **Create Token** › **Custom token**.
3. Under **Permissions**, choose **Account › Radar › Read**.
4. Under **Account Resources**, choose **Include** and select your account.
5. Create the token and put it in `.env` as `CLOUDFLARE_API_TOKEN=...` (no quotes).
6. Restart `node server.js`. The log should say `Cloudflare Radar: enabled`.

Use an **API Token**, not the Global API Key.

## Data sources

| Feature | Source | Data window | Server cache |
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

The browser polls the local server every 5–30 minutes. The server cache decides how often each
upstream API is actually contacted.

### Alert severity

Feeds don't share a severity scale, so the dashboard applies a transparent triage rule
(`buildAlerts()` in `js/main.js`):

- **Critical:** a KEV entry with known ransomware use, or EPSS ≥ 95th percentile
- **High:** any other KEV addition (last 30 days), a press-reported attack, or a nationwide internet outage
- **Medium:** a ransomware leak-site post, or a regional outage
- **Low:** an online botnet C2 server

Alerts are ordered newest day first, most severe first within each day.

## How it works

```
server.js          zero-dependency Node proxy + static server: fetch, cache, normalise each source
js/data.js         reference data only (ISO country table, source attributions, port names)
js/api.js          polls /api/* and keeps the last good data per source
js/globe.js        globe.gl heatmap, corridors and C2 markers
js/panels.js       renderers for each panel
js/main.js         maps source data onto the views
css/styles.css     theme + layout
```

The server exposes `/api/kev`, `/api/ransomware`, `/api/dshield`, `/api/abusech`, `/api/radar`
and `/api/status`. Each API response includes `fetchedAt`, and a `stale` flag when the upstream
failed and the last good data is being served. `window.AEGIS` exposes the data store and globe in
the browser DevTools console for experimentation.

## Security

- **Secrets:** the Radar token lives only in `.env`, which `.gitignore` excludes. It is sent
  only to `api.cloudflare.com`, redacted from all logs and error messages, and never reaches the browser.
- **Static files:** only `index.html`, `css/*.css` and `js/*.js` are served. Dotfiles,
  `server.js`, path traversal and malformed URLs are rejected.
- **Local only by default:** the server binds to `127.0.0.1`, and requests addressed to any
  other hostname are refused (a guard against DNS rebinding).
- **Untrusted feed content:** all feed text is HTML-escaped, links are restricted to `http(s)`,
  and malicious URLs and IPs are defanged (`hxxp`, `[.]`).
- **Security headers:** a strict Content-Security-Policy, plus `X-Frame-Options`,
  `Referrer-Policy` and `nosniff`. Every CDN script and the map data are pinned with
  Subresource Integrity hashes.

Found a security issue? Please open a GitHub issue without exploit details, or contact the
maintainer through GitHub.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Banner: "Page opened as a file" | Run `node server.js` and open http://localhost:8080 |
| `EADDRINUSE` on start | Another copy is already running: `pkill -f "node server.js"`, or set a different `PORT` |
| Radar still shows "needs a token" after editing `.env` | Restart the server; `.env` is read only at startup |
| "Scanners" button greyed out after starting | Normal for about 30 s while attacker IPs are geolocated |
| A source shows "rate limited" | ransomware.live allows 1 request/min per endpoint; the cache retries automatically |

## Usage terms and etiquette

The **code** is MIT-licensed, but each **data source** has its own terms, and several are
**non-commercial**:

- **ransomware.live:** the free API is for personal, non-commercial use and allows 1 request/min
  per endpoint. The server caches for 30 min (past months for 12 h) and spaces its calls out.
  For anything beyond personal use, get a free PRO key from ransomware.live.
- **SANS ISC / DShield:** CC BY-NC-SA. Set `CONTACT_EMAIL` so they can reach you if your usage causes problems.
- **Cloudflare Radar:** CC BY-NC 4.0.
- **abuse.ch (URLhaus, Feodo Tracker):** CC0.
- **CISA KEV:** U.S. Government work. **FIRST EPSS:** free to use with attribution.

Deploying this dashboard commercially requires checking each provider's terms first.

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
- Country reference table in `js/data.js` derived from [mledoze/countries](https://github.com/mledoze/countries),
  licensed under the [Open Database License (ODbL) 1.0](https://opendatacommons.org/licenses/odbl/1.0/)
- Fonts: Rajdhani, Inter and JetBrains Mono via Google Fonts (SIL Open Font License)
- Threat data from the providers listed in [Data sources](#data-sources)

## License

The code is released under the [MIT License](LICENSE): you are free to use, modify and distribute it,
including commercially, as long as the copyright notice is kept. The MIT license covers this
repository's code only. It does not cover the threat data, which remains under each provider's
terms (see [Usage terms](#usage-terms-and-etiquette)), or the country table, which is ODbL 1.0.
