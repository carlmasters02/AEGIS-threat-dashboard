# AEGIS — Global Cyber Threat Operations Dashboard

A SOC-style dashboard with a 3D threat heatmap globe and live intel panels, built entirely on
**real, public threat-intelligence feeds**. Nothing is simulated: if a source is unavailable,
its panels say so instead of inventing numbers.

## Run it

```bash
node server.js          # Node 18+, no npm install needed
# open http://localhost:8080
```

The page must be opened through the server (not as a `file://`). Most feeds don't allow direct
browser requests, and some need keys that must stay private, so `server.js` fetches, caches and
normalises them.

### Optional: enable Cloudflare Radar (recommended)

Radar is the only free source with **country-to-country attack flows**, so without it the globe
has no attack arcs. To enable it:

1. Create a free Cloudflare account, then go to https://dash.cloudflare.com/profile/api-tokens
   and choose **Create Custom Token**. Set the permission to **Account › Radar › Read**.
2. `cp .env.example .env` and set `CLOUDFLARE_API_TOKEN=...`
3. Restart `node server.js`

## Where each feature's data comes from

| Feature | Source | Window / refresh |
|---|---|---|
| Threat level gauge | [SANS ISC Infocon](https://isc.sans.edu/infocon.html) | live |
| Big counter, KPI "DShield reports" | [DShield daily summary](https://isc.sans.edu/api/) — firewall/honeypot log lines from volunteer sensors | previous day |
| Globe heat: **L7 targets / L7 origins / DDoS targets** | [Cloudflare Radar](https://radar.cloudflare.com/security) attack share by country | 24h, 15 min cache |
| Globe heat: **Ransomware** | [ransomware.live](https://www.ransomware.live) leak-site victims per country | 30 days |
| Globe heat: **Scanners** | DShield top 40 attacking IPs, grouped by the IP's AS registration country | latest day |
| Globe arcs (attack corridors) | Radar top origin→target pairs (share of L7 attacks) | 24h |
| Globe cyan rings | [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) botnet C2 servers by country | live |
| Event stream (bottom right) | [abuse.ch URLhaus](https://urlhaus.abuse.ch/) newest malware URLs (defanged) | 15 min cache |
| Ransomware Group Leaderboard | ransomware.live victims per group, daily sparkline, change vs prior 30 days | 30 days |
| Threat Intel Alerts | CISA KEV additions, press-reported attacks, leak-site posts, Radar outages, online botnet C2s | see below |
| Attack Vectors | Radar DDoS vectors / web attack types / mitigation / industries, DShield probed ports, ransomware sectors, URLhaus malware tags | per dataset |
| Most Targeted | Mirrors whichever globe heat layer is selected | — |
| Activity Trend | Radar L7 & L3 volume (7d hourly), ransomware victims/day, DShield reports/day, URLhaus URLs/hour | per dataset |
| Known Exploited Vulnerabilities | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) + [FIRST EPSS](https://www.first.org/epss/) exploit probability | daily |
| Intel ticker | Headlines built from the same feeds | — |

The **Sources** button in the header shows each feed's live status, when it last updated and its license.

### Alert severity

Feeds don't share a severity scale, so the dashboard applies a transparent triage rule
(`buildAlerts()` in `js/main.js`):

- **Critical:** a KEV entry with known ransomware use, or EPSS ≥ 95th percentile
- **High:** any other KEV addition, a press-reported attack, or a nationwide internet outage
- **Medium:** a ransomware leak-site post, or a regional outage
- **Low:** an online botnet C2 server

## Code layout

```
server.js          proxy + static server: fetch, cache, normalise each source
js/data.js         reference data only (ISO country table, source attributions, port names)
js/api.js          polls /api/* and keeps last-good data per source
js/globe.js        globe.gl heatmap, corridors, C2 markers
js/panels.js       renderers for each panel
js/main.js         maps source data onto the views
css/styles.css     theme + layout
```

`server.js` exposes `/api/kev`, `/api/ransomware`, `/api/dshield`, `/api/abusech`, `/api/radar`
and `/api/status`. It only serves `index.html`, `css/` and `js/` as static files; `.env` is never exposed.

## Security

- **Secrets:** the Radar token lives only in `.env`, which `.gitignore` excludes. It is sent
  only to `api.cloudflare.com`, redacted from all logs and error messages, and never reaches the browser.
- **Static files:** the server only serves `index.html` and `css/*.css` / `js/*.js`. Dotfiles,
  `server.js`, path traversal and malformed URLs are rejected.
- **Local only by default:** the server binds to `127.0.0.1`, and requests addressed to any
  other hostname are refused (a guard against DNS rebinding).
- **Untrusted feed content:** all feed text is HTML-escaped, links are restricted to `http(s)`,
  and malicious URLs/IPs are defanged.
- **Security headers:** a strict Content-Security-Policy, plus `X-Frame-Options`,
  `Referrer-Policy` and `nosniff`. Every CDN script and the map data are pinned with
  Subresource Integrity hashes.

## Usage terms and etiquette

- **ransomware.live** free API is for personal, non-commercial use and allows 1 request/min per
  endpoint. The server caches for 30 min (past months for 12 h) and spaces its calls out. For
  anything beyond personal use, get a free PRO key from ransomware.live.
- **SANS ISC / DShield** data is CC BY-NC-SA. Set `CONTACT_EMAIL` in `.env` so they can reach
  you if your usage causes problems.
- **Cloudflare Radar** data is CC BY-NC 4.0. **abuse.ch** data is CC0. **CISA KEV** is a U.S.
  Government work.
- Malware URLs and C2 addresses are shown **defanged** (`hxxp`, `[.]`), so they can't be clicked by accident.

## Known limits

- There is no free, global, per-event "live attack" feed. Commercial threat maps use their own
  sensor networks. The arcs here are Cloudflare's real aggregate attack corridors, not individual attacks.
- The "Scanners" layer uses the attacking IP's **network registration country** (from ISC),
  which is not always where the machine physically is. Cloud providers often register addresses
  in their home country.
- The ransomware.live free API may lag its PRO API by a few hours.
