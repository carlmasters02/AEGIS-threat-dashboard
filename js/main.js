/* ==========================================================================
   Wiring: real data sources (via Api) -> globe + panels.
   Nothing here generates data; every view derives from Api.data(...).
   ========================================================================== */

(function main() {
  const radar = () => Api.data('radar');
  const radarOn = () => radar()?.configured === true;
  const radarPart = name => radar()?.parts?.[name] || null;
  const rw = () => Api.data('ransomware');
  const ds = () => Api.data('dshield');
  const ab = () => Api.data('abusech');
  const kev = () => Api.data('kev');

  let heatModeId = null;
  let heatModeChosen = false;   // user picked a layer; otherwise follow the best available
  let trackedGroup = null;
  let openCc = null;

  const toMap = rows => (rows && rows.length ? Object.fromEntries(rows.map(r => [r.cc, r.value])) : null);
  const nonEmpty = obj => (obj && Object.keys(obj).length ? obj : null);
  const whyMissing = key => {
    if (key === 'radar' && radar()?.configured === false) return 'needs a Cloudflare Radar token';
    const st = Api.state[key];
    if (!st || st.loading) return 'loading…';
    return st.error ? 'source unavailable' : 'no data';
  };

  /* ---------------- heat layers: each is one real per-country metric ---------------- */

  const HEAT_MODES = [
    { id: 'l7target', chip: 'L7 targets', title: 'Layer 7 (HTTP) attack targets', window: 'Cloudflare Radar · last 24h',
      unit: '% of attacks', percent: true, source: 'radar', values: () => toMap(radarPart('l7Targets')) },
    { id: 'l7origin', chip: 'L7 origins', title: 'Layer 7 (HTTP) attack origins', window: 'Cloudflare Radar · last 24h',
      unit: '% of attacks', percent: true, source: 'radar', values: () => toMap(radarPart('l7Origins')) },
    { id: 'l3target', chip: 'DDoS targets', title: 'Layer 3/4 DDoS targets', window: 'Cloudflare Radar · last 24h',
      unit: '% of attacks', percent: true, source: 'radar', values: () => toMap(radarPart('l3Targets')) },
    { id: 'ransomware', chip: 'Ransomware', title: 'Ransomware leak-site victims', window: 'ransomware.live · last 30 days',
      unit: 'victims', source: 'ransomware', values: () => {
        const d = rw();
        if (!d) return null;
        if (trackedGroup) return nonEmpty(d.groups.find(g => g.name === trackedGroup)?.countries);
        return nonEmpty(d.countries);
      } },
    { id: 'honeypot', chip: 'Scanners', title: 'Top attacking IPs by network country', window: 'DShield top 40 source IPs · AS registration country',
      unit: 'reports', source: 'dshield', values: () => nonEmpty(ds()?.countries) },
  ];
  const modeById = id => HEAT_MODES.find(m => m.id === id);
  const heatMode = () => modeById(heatModeId);
  const formatModeValue = (mode, v) => (mode.percent ? pct(v, v < 1 ? 2 : 1) : compact(v));

  function pickDefaultMode() {
    if (heatModeChosen && heatModeId && heatMode().values()) return;
    const first = HEAT_MODES.find(m => m.values());
    if (first) heatModeId = first.id;
  }

  function setHeatMode(id) {
    heatModeId = id;
    heatModeChosen = true;
    renderHeat();
    renderTargets();
  }

  function renderHeatChips() {
    const box = $('#heatModes');
    box.innerHTML = '';
    for (const m of HEAT_MODES) {
      const available = !!m.values();
      const b = el('button', `chip-btn heat-chip${m.id === heatModeId ? ' is-on' : ''}`);
      b.textContent = m.chip;
      b.setAttribute('role', 'radio');
      b.setAttribute('aria-checked', String(m.id === heatModeId));
      b.disabled = !available;
      b.title = available ? `${m.title} — ${m.window}` : `${m.title} — ${whyMissing(m.source)}`;
      b.addEventListener('click', () => setHeatMode(m.id));
      box.appendChild(b);
    }
  }

  function renderHeat() {
    pickDefaultMode();
    renderHeatChips();
    const mode = heatMode();
    const values = mode?.values() || {};
    globeView.setHeat(values);

    $('#legendTitle').textContent = mode
      ? `${mode.title}${trackedGroup && mode.id === 'ransomware' ? ` · ${trackedGroup}` : ''}`
      : 'Heat layer — waiting for data';
    const max = Math.max(0, ...Object.values(values));
    $('#legendMin').textContent = '0';
    $('#legendMax').textContent = mode && max ? formatModeValue(mode, max) : '—';
    $('#legendUnit').textContent = mode ? `${mode.unit} · ${mode.window.split(' · ').pop()}` : '';

    const notes = [];
    notes.push(corridorCount()
      ? `<span><i class="sw arc"></i>Top ${corridorCount()} L7 attack corridors · Radar 24h</span>`
      : `<span class="dim"><i class="sw arc"></i>Attack corridors ${radarOn() ? 'unavailable' : 'need a Cloudflare Radar token'}</span>`);
    if (ab()?.feodo?.total) notes.push(`<span><i class="sw ring"></i>Botnet C2 hosting countries · Feodo Tracker</span>`);
    $('#legendNotes').innerHTML = notes.join('');
  }

  /* ---------------- globe ---------------- */

  const globeView = new GlobeView($('#globe'), {
    onCountryClick: cc => openCountry(cc),
    labelFor: countryTooltip,
  });

  globeView.init()
    .then(() => {
      $('#globeLoading').remove();
      renderAll();
    })
    .catch(err => {
      console.error(err);
      const n = $('#globeLoading');
      n.classList.add('error');
      n.textContent = 'Could not load the globe (needs an internet connection for the map data).';
    });

  /* Cross-border corridors only; Radar also reports domestic pairs (e.g. US → US), which can't be drawn as arcs. */
  function corridorPairs() {
    return (radarPart('l7Pairs') || radarPart('l3Pairs') || []).filter(p => p.from !== p.to);
  }
  const corridorCount = () => corridorPairs().length;

  function renderGlobeLayers() {
    const layer = radarPart('l7Pairs') ? 'L7' : 'L3/4';
    globeView.setCorridors(corridorPairs().map(p => ({
      ...p,
      label: `<div class="globe-tip"><h4>${esc(p.from)} → ${esc(p.to)}</h4>
        <div class="row">${esc(p.fromName || countryName(p.from))} → ${esc(p.toName || countryName(p.to))}</div>
        <div class="row">Share of ${layer} attacks <b>${pct(p.value, 2)}</b></div>
        <div class="hint">Cloudflare Radar · last 24h</div></div>`,
    })));

    const c2 = ab()?.feodo?.byCountry || {};
    const maxC2 = Math.max(1, ...Object.values(c2));
    globeView.setMarkers(Object.entries(c2).map(([cc, n]) => ({ cc, weight: n / maxC2 })));
    $('#miniCorridors').textContent = corridorCount() || '—';
  }

  function countryTooltip(f) {
    const name = f.cc ? countryName(f.cc) : f.properties.name;
    const rows = [];
    for (const m of HEAT_MODES) {
      const v = f.cc && m.values()?.[f.cc];
      if (v) rows.push(`<div class="row">${esc(m.chip)} <b>${formatModeValue(m, v)}</b></div>`);
    }
    const c2 = f.cc && ab()?.feodo?.byCountry?.[f.cc];
    if (c2) rows.push(`<div class="row">Botnet C2 servers <b>${c2}</b></div>`);
    return `<div class="globe-tip"><h4>${esc(name)}</h4>
      ${rows.join('') || '<div class="row">No activity in the loaded datasets</div>'}
      ${f.cc ? '<div class="hint">Click for details</div>' : ''}</div>`;
  }

  /* ---------------- country card ---------------- */

  const card = $('#countryCard');

  function openCountry(cc) {
    if (!COUNTRY_REF[cc]) return;
    openCc = cc;
    card.hidden = false;
    renderCountry();
    globeView.focus(cc);
  }

  function renderCountry() {
    if (!openCc) return;
    const cc = openCc;
    const stats = HEAT_MODES.map(m => {
      const vals = m.values();
      if (!vals) return null;
      const ranked = Object.entries(vals).sort((a, b) => b[1] - a[1]);
      const i = ranked.findIndex(([k]) => k === cc);
      return `<div title="${esc(m.title)} — ${esc(m.window)}"><b>${i >= 0 ? formatModeValue(m, ranked[i][1]) : '—'}</b>
        <span>${esc(m.chip)}${i >= 0 ? ` · #${i + 1}` : ''}</span></div>`;
    }).filter(Boolean).join('');

    const section = (title, rows, empty) => `<div class="cc-section">${esc(title)}</div>
      <ul class="cc-list">${rows.length ? rows.join('') : `<li><span class="dim">${esc(empty)}</span><span></span></li>`}</ul>`;

    const d = rw();
    const groups = d ? d.groups.map(g => [g.name, g.countries[cc] || 0]).filter(([, n]) => n).sort((a, b) => b[1] - a[1]).slice(0, 4) : [];
    const victims = d ? d.latest.filter(v => v.country === cc).slice(0, 4) : [];
    const scanners = (ds()?.attackers || []).filter(a => a.cc === cc).slice(0, 4);
    const c2 = (ab()?.feodo?.servers || []).filter(s => s.country === cc).slice(0, 3);
    const pairs = corridorPairs().filter(p => p.to === cc || p.from === cc).slice(0, 4);

    $('#countryCardBody').innerHTML = `
      <div class="cc-code">${esc(cc)}</div>
      <div class="cc-name">${esc(countryName(cc))}</div>
      <div class="cc-stats">${stats || '<div><b>—</b><span>No data yet</span></div>'}</div>
      ${radarOn() ? section('Attack corridors · Radar 24h', pairs.map(p =>
        `<li><span>${esc(p.from)} → ${esc(p.to)}</span><span>${pct(p.value, 2)}</span></li>`), 'Not in the top corridors') : ''}
      ${section('Ransomware groups · 30d', groups.map(([g, n]) => `<li><span>${esc(g)}</span><span>${n}</span></li>`),
        d ? 'No leak-site victims in window' : whyMissing('ransomware'))}
      ${victims.length ? section('Latest leak-site posts', victims.map(v =>
        `<li><span>${esc(v.victim)}</span><span>${relTime(v.discovered)}</span></li>`), '') : ''}
      ${section('Top scanners from this country · DShield', scanners.map(a =>
        `<li><span class="mono">${esc(a.ip)}</span><span>${compact(a.reports)}</span></li>`),
        ds() ? 'None in the top 40 source IPs' : whyMissing('dshield'))}
      ${c2.length ? section('Botnet C2 servers · Feodo', c2.map(s =>
        `<li><span>${esc(s.malware)} ${esc(s.ip)}:${esc(s.port)}</span><span>${esc(s.status)}</span></li>`), '') : ''}`;
  }

  $('#countryClose').addEventListener('click', () => {
    openCc = null;
    card.hidden = true;
    globeView.clearSelection();
  });

  /* ---------------- ransomware group tracking ---------------- */

  function trackGroup(name) {
    trackedGroup = name;
    Actors.setTracked(name);
    $('#groupFilter').hidden = !name;
    if (name) {
      $('#groupFilterName').textContent = name;
      heatModeId = 'ransomware';
      heatModeChosen = true;
    }
    renderHeat();
    renderTargets();
  }
  $('#groupFilterClear').addEventListener('click', () => trackGroup(null));

  /* ---------------- panels ---------------- */

  KPI.init();
  ThreatLevel.init();
  Actors.init(trackGroup);
  Alerts.init(openCountry);
  Kev.init();
  Stream.init();
  Ticker.init();
  startClocks();
  const trend = new TrendChart($('#timeline'), $('#timelineEmpty'));
  const vectorBars = new BarList($('#vectorList'), $('#vectorFoot'));
  const targetBars = new BarList($('#targetList'), $('#targetFoot'), { onRowClick: openCountry });

  /* Select helper: options whose data isn't available are disabled with the reason. */
  function fillSelect(select, options, current) {
    const value = options.some(o => o.id === current && o.available()) ? current
      : (options.find(o => o.available()) || options[0]).id;
    select.innerHTML = options.map(o =>
      `<option value="${o.id}" ${o.available() ? '' : 'disabled'}>${esc(o.label)}${o.available() ? '' : ` — ${esc(whyMissing(o.source))}`}</option>`).join('');
    select.value = value;
    return value;
  }

  /* ---- Most targeted: mirrors the globe heat layer ---- */

  function renderTargets() {
    const select = $('#targetSelect');
    const opts = HEAT_MODES.map(m => ({ id: m.id, label: m.title, source: m.source, available: () => !!m.values() }));
    fillSelect(select, opts, heatModeId);
    const mode = heatMode();
    const values = mode?.values();
    if (!mode || !values) {
      targetBars.render([], { empty: `Waiting for data (${whyMissing(mode?.source || 'ransomware')})` });
      return;
    }
    const total = Object.values(values).reduce((s, v) => s + v, 0);
    const rows = Object.entries(values).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([cc, v]) => ({
      key: cc, code: cc, label: countryName(cc), value: v,
      display: formatModeValue(mode, v),
      side: mode.percent ? '' : `${Math.round((v / total) * 100)}%`,
    }));
    targetBars.render(rows, {
      dataset: `${mode.id}:${trackedGroup || ''}`,
      foot: `${esc(mode.window)}${trackedGroup && mode.id === 'ransomware' ? ` · group: ${esc(trackedGroup)}` : ''}`,
    });
  }
  $('#targetSelect').addEventListener('change', e => setHeatMode(e.target.value));

  /* ---- Attack vectors ---- */

  const summaryRows = list => (list || []).slice(0, 9).map(r => ({ key: r.label, label: r.label, value: r.value, display: pct(r.value) }));
  const VECTOR_SETS = [
    { id: 'l3v', label: 'DDoS vectors · Radar 7d', source: 'radar', foot: 'Share of L3/4 DDoS attacks by vector · Cloudflare Radar',
      rows: () => summaryRows(radarPart('l3Vectors')) },
    { id: 'l7r', label: 'Web attack types · Radar 7d', source: 'radar', foot: 'Share of mitigated L7 attacks by managed rule category · Cloudflare Radar',
      rows: () => summaryRows(radarPart('l7Rules')) },
    { id: 'l7m', label: 'L7 mitigation · Radar 7d', source: 'radar', foot: 'Share of mitigated L7 requests by product · Cloudflare Radar',
      rows: () => summaryRows(radarPart('l7Mitigation')) },
    { id: 'ind', label: 'Targeted industries · Radar 7d', source: 'radar', foot: 'Share of L7 attacks by targeted industry · Cloudflare Radar',
      rows: () => summaryRows(radarPart('l7Industry')) },
    { id: 'ports', label: 'Most probed ports · DShield', source: 'dshield', foot: 'Reports per destination port, latest day · SANS ISC DShield',
      rows: () => {
        const ports = ds()?.ports || [];
        const total = ports.reduce((s, p) => s + p.records, 0);
        return ports.slice(0, 9).map(p => ({
          key: String(p.port), label: `${p.port} ${PORT_NAMES[p.port] || ''}`.trim(), value: p.records,
          display: compact(p.records), side: total ? `${Math.round((p.records / total) * 100)}%` : '' }));
      } },
    { id: 'sectors', label: 'Ransomware sectors · 30d', source: 'ransomware', foot: 'Leak-site victims by sector, last 30 days · ransomware.live',
      rows: () => {
        const d = rw();
        if (!d) return [];
        return d.sectors.slice(0, 9).map(([s, n]) => ({ key: s, label: s, value: n, display: fmt(n), side: `${Math.round((n / d.total30) * 100)}%` }));
      } },
    { id: 'malware', label: 'Malware families · URLhaus 24h', source: 'abusech', foot: 'Tags on malware URLs reported in the last 24h · abuse.ch URLhaus',
      rows: () => (ab()?.urlhaus?.tags || []).slice(0, 9).map(([t, n]) => ({ key: t, label: t, value: n, display: fmt(n) })) },
  ];
  let vectorSet = null;       // null = automatic (first available in preference order)

  function renderVectors() {
    const opts = VECTOR_SETS.map(v => ({ ...v, available: () => v.rows().length > 0 }));
    const shown = fillSelect($('#vectorSelect'), opts, vectorSet);
    const set = VECTOR_SETS.find(v => v.id === shown);
    const rows = set.rows();
    vectorBars.render(rows, { dataset: set.id, foot: esc(set.foot), empty: `No data (${whyMissing(set.source)})` });
  }
  $('#vectorSelect').addEventListener('change', e => { vectorSet = e.target.value; renderVectors(); });

  /* ---- Activity trend ---- */

  const hourFmt = d => { const t = new Date(d); return `${pad2(t.getUTCHours())}:00Z`; };
  const radarSeriesFoot = s => `Cloudflare Radar · hourly${s?.normalization ? ` · normalized (${esc(s.normalization.toLowerCase().replace(/_/g, ' '))})` : ''}`;
  const TREND_SETS = [
    { id: 'l7', label: 'L7 attack volume · Radar 7d', source: 'radar',
      points: () => radarPart('l7Series')?.points, foot: () => radarSeriesFoot(radarPart('l7Series')), y: v => v.toFixed(2) },
    { id: 'l3', label: 'L3/4 DDoS volume · Radar 7d', source: 'radar',
      points: () => radarPart('l3Series')?.points, foot: () => radarSeriesFoot(radarPart('l3Series')), y: v => v.toFixed(2) },
    { id: 'rw', label: 'Ransomware victims / day · 30d', source: 'ransomware',
      points: () => rw()?.daily, foot: () => 'Leak-site posts per day (UTC) · ransomware.live' },
    { id: 'ds', label: 'DShield reports / day · 30d', source: 'dshield',
      points: () => ds()?.daily?.map(d => ({ date: `${d.date}T00:00:00Z`, value: d.records })), foot: () => 'Firewall/honeypot log lines submitted per day · SANS ISC DShield' },
    { id: 'uh', label: 'Malware URLs / hour · 24h', source: 'abusech',
      points: () => ab()?.urlhaus?.hourly, foot: () => 'New malware distribution URLs per hour · abuse.ch URLhaus', x: hourFmt },
  ];
  let trendSet = null;        // null = automatic

  function renderTrend() {
    const opts = TREND_SETS.map(t => ({ ...t, available: () => (t.points() || []).length > 1 }));
    const shown = fillSelect($('#timelineSelect'), opts, trendSet);
    const set = TREND_SETS.find(t => t.id === shown);
    const points = set.points();
    if (points && points.length > 1) {
      trend.setSeries(points, { xFormat: set.x || shortDate, yFormat: set.y || compact });
      $('#timelineFoot').innerHTML = set.foot();
    } else {
      trend.setEmpty(`No data (${whyMissing(set.source)})`);
      $('#timelineFoot').textContent = '';
    }
  }
  $('#timelineSelect').addEventListener('change', e => { trendSet = e.target.value; renderTrend(); });

  /* ---- KPIs + header ---- */

  function renderKpis() {
    const dsd = ds();
    if (dsd?.daily?.length) {
      const [prev, last] = dsd.daily.slice(-2);
      KPI.set('dshield', { value: last.records, label: `DShield reports · ${shortDate(`${last.date}T00:00:00Z`)}`,
        sub: deltaHtml(last.records, prev?.records, { suffix: ' vs prior day' }),
        title: `${fmt(last.records)} log lines from ${fmt(last.sources)} source IPs against ${fmt(last.targets)} sensor IPs` });
      tweenNumber($('#bigCounter'), last.records, fmt);
      $('#bigCounterLabel').textContent = `firewall & honeypot reports to DShield · ${shortDate(`${last.date}T00:00:00Z`)}`;
      tweenNumber($('#miniSources'), last.sources, compact);
    } else {
      KPI.set('dshield', { value: null, sub: esc(whyMissing('dshield')) });
    }

    const r = rw();
    KPI.set('ransom', r
      ? { value: r.last7d, format: fmt, sub: deltaHtml(r.last7d, r.prior7d, { suffix: ' vs prior 7d' }),
          title: `${r.last24h} in the last 24h · ${r.total30} in 30 days across ${r.groupsActive30} groups` }
      : { value: null, sub: esc(whyMissing('ransomware')) });

    const k = kev();
    KPI.set('kev', k
      ? { value: k.added30, format: fmt, sub: `${k.added7} this week · ${fmt(k.total)} total`,
          title: `${k.ransomwareKnown} catalogue entries are known to be used in ransomware campaigns` }
      : { value: null, sub: esc(whyMissing('kev')) });

    const u = ab()?.urlhaus;
    KPI.set('urlhaus', u
      ? { value: u.added24h, format: fmt, sub: `${fmt(u.online)} online now`, title: `${fmt(u.total)} URLs reported in the last 30 days` }
      : { value: null, sub: esc(whyMissing('abusech')) });

    const outages = radarPart('outages');
    if (outages) {
      KPI.set('fifth', { label: 'Internet outages · 7d', value: outages.length, format: fmt,
        sub: `${outages.filter(o => !o.end).length} ongoing · Radar` });
    } else if (ab()?.feodo) {
      const f = ab().feodo;
      KPI.set('fifth', { label: 'Botnet C2 servers', value: f.total, format: fmt, sub: `${f.online} online · Feodo Tracker`,
        title: f.byMalware.map(([m, n]) => `${m}: ${n}`).join(', ') });
    } else {
      KPI.set('fifth', { value: null, sub: esc(whyMissing('radar')) });
    }

    ThreatLevel.render(dsd?.infocon);
  }

  function renderSourcesBadge() {
    const keys = Object.keys(SOURCES);
    const live = keys.filter(k => ['ok', 'stale'].includes(sourceStatus(k, Api.state[k]).cls)).length;
    const loading = keys.some(k => sourceStatus(k, Api.state[k]).cls === 'loading');
    $('#sourcesSummary').textContent = loading && !live ? 'CONNECTING…' : `${live}/${keys.length} SOURCES LIVE`;
    $('#sourcesBtn').classList.toggle('degraded', live < keys.length);
    $('#sourcesBtn').classList.toggle('down', !loading && live === 0);
    renderSources(Api.state);

    const unreachable = keys.every(k => (Api.state[k]?.error || '').match(/file|unreachable/i));
    const banner = $('#banner');
    banner.hidden = !unreachable;
    if (unreachable) banner.textContent = Api.state[keys[0]].error;
  }

  /* ---- Alerts: merged from real feeds. Severity is this dashboard's triage heuristic:
       KEV: critical if known ransomware use or EPSS ≥ 95th percentile, else high
       Press-reported ransomware attack: high · Leak-site post: medium
       Radar outage: high if nationwide, else medium · Online botnet C2: low ---- */

  const humanize = v => (v ? String(v).replace(/_/g, ' ').toLowerCase() : null);   // POWER_OUTAGE -> power outage

  function buildAlerts() {
    const items = [];
    const now = Date.now();
    for (const v of kev()?.recent || []) {
      const t = Date.parse(`${v.dateAdded}T00:00:00Z`);
      if (now - t > 30 * 864e5) continue;
      const hot = v.ransomware || (v.epss && v.epss.percentile >= 0.95);
      items.push({
        id: `kev:${v.cve}`, sev: hot ? 'critical' : 'high', t, dateOnly: true, source: 'CISA KEV',
        title: v.name, url: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}`,
        meta: [v.cve, `${v.vendor} ${v.product}`, v.epss ? `EPSS ${(v.epss.score * 100).toFixed(1)}%` : null,
          `patch by ${v.dueDate}`, v.ransomware ? 'RANSOMWARE USE' : null],
      });
    }
    for (const p of rw()?.press || []) {
      const t = Date.parse(p.date);
      if (!isFinite(t)) continue;
      items.push({
        id: `press:${p.title}:${p.date}`, sev: 'high', t, dateOnly: true, source: 'Press',
        title: p.title, url: p.url, cc: COUNTRY_REF[p.country] ? p.country : null,
        meta: [p.group && `claimed by ${p.group}`, p.country && countryName(p.country)],
      });
    }
    for (const v of (rw()?.latest || []).slice(0, 30)) {
      items.push({
        id: `leak:${v.group}:${v.victim}`, sev: 'medium', t: Date.parse(v.discovered), source: 'Leak site',
        title: `${v.victim} listed by ${v.group}`, url: v.url, cc: COUNTRY_REF[v.country] ? v.country : null,
        meta: [v.country && countryName(v.country), v.sector],
      });
    }
    for (const o of radarPart('outages') || []) {
      const cc = o.locations[0]?.cc;
      items.push({
        id: `outage:${o.id}`, sev: /nationwide/i.test(o.scope || o.type || '') ? 'high' : 'medium',
        t: Date.parse(o.start), source: 'Radar outage',
        title: o.description || `Internet outage: ${o.locations.map(l => l.name).join(', ')}`,
        url: o.url, cc: COUNTRY_REF[cc] ? cc : null,
        meta: [o.locations.map(l => l.name).join(', '), humanize(o.cause), humanize(o.type), o.end ? `ended ${relTime(o.end)}` : 'ONGOING'],
      });
    }
    for (const s of (ab()?.feodo?.servers || []).filter(x => x.status === 'online')) {
      items.push({
        id: `c2:${s.ip}:${s.port}`, sev: 'low', t: Date.parse(`${s.lastOnline}T00:00:00Z`), dateOnly: true, source: 'Feodo Tracker',
        title: `${s.malware} botnet C2 online at ${s.ip.replace(/\./g, '[.]')}:${s.port}`,
        url: `https://feodotracker.abuse.ch/browse/host/${encodeURIComponent(s.ip)}/`, cc: COUNTRY_REF[s.country] ? s.country : null,
        meta: [s.asname, s.country && countryName(s.country), `first seen ${s.firstSeen.slice(0, 10)}`],
      });
    }
    const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
    const day = t => Math.floor(t / 864e5);
    return items.filter(i => isFinite(i.t))
      .sort((a, b) => day(b.t) - day(a.t) || SEV_RANK[a.sev] - SEV_RANK[b.sev] || b.t - a.t)
      .slice(0, 100);
  }

  function renderAlerts() {
    const any = ['kev', 'ransomware', 'radar', 'abusech'].some(k => Api.data(k));
    Alerts.render(buildAlerts(), any ? 'No alerts in window' : 'Waiting for intel feeds…');
  }

  /* ---- Ticker: real headlines only ---- */

  function feedTicker() {
    for (const v of (kev()?.recent || []).slice(0, 6)) {
      Ticker.push(`<b>CISA KEV</b> ${esc(v.cve)} — ${esc(v.name)} (added ${esc(v.dateAdded)})`, 'var(--high)', `kev:${v.cve}`);
    }
    for (const p of (rw()?.press || []).slice(0, 6)) {
      Ticker.push(`<b>PRESS</b> ${esc(p.title)}${p.group ? ` — claimed by ${esc(p.group)}` : ''}`, 'var(--crit)', `press:${p.title}`);
    }
    for (const o of (radarPart('outages') || []).slice(0, 4)) {
      Ticker.push(`<b>OUTAGE</b> ${esc(o.description || o.locations.map(l => l.name).join(', '))}`, 'var(--med)', `outage:${o.id}`);
    }
    const r = rw();
    if (r?.groups?.[0]) {
      const g = r.groups[0];
      Ticker.push(`<b>RANSOMWARE</b> ${esc(g.name)} leads leak-site activity with ${g.count} victims in 30 days; ${r.total30} victims across ${r.groupsActive30} groups overall`,
        'var(--accent-2)', `rwtop:${g.name}:${g.count}`);
    }
    const d = ds();
    if (d?.ports?.[0]) {
      const p = d.ports[0];
      Ticker.push(`<b>DSHIELD</b> Most probed port: ${p.port}${PORT_NAMES[p.port] ? ` (${PORT_NAMES[p.port]})` : ''} — ${compact(p.records)} reports from ${fmt(p.sources)} sources`,
        'var(--cyan)', `port:${p.port}:${p.records}`);
    }
    const u = ab()?.urlhaus;
    if (u?.tags?.[0]) {
      Ticker.push(`<b>URLHAUS</b> ${fmt(u.added24h)} new malware URLs in 24h; most common tag: ${esc(u.tags[0][0])} (${u.tags[0][1]})`,
        'var(--crit)', `uh:${u.added24h}`);
    }
  }

  /* ---------------- update plumbing ---------------- */

  function renderAll() {
    renderHeat();
    renderGlobeLayers();
    renderTargets();
    renderVectors();
    renderTrend();
    renderKpis();
    renderAlerts();
    renderCountry();
    renderSourcesBadge();
    feedTicker();

    const r = rw();
    Actors.render(r?.groups, r ? 'No victims in window' : `ransomware.live: ${whyMissing('ransomware')}`);
    if (r) $('#actorsMeta').textContent = `victims claimed · 30d · ${r.groupsActive30} active`;
    Kev.render(kev(), `CISA KEV: ${whyMissing('kev')}`);
    Stream.render(ab()?.urlhaus?.latest, `URLhaus: ${whyMissing('abusech')}`);
  }

  let renderQueued = false;
  Api.onUpdate(() => {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => { renderQueued = false; renderAll(); });
  });
  Api.start();
  renderAll();

  // Keep relative times ("5m ago") and source ages honest.
  setInterval(() => { renderAlerts(); renderSourcesBadge(); }, 60 * 1000);

  window.AEGIS = { Api, globeView };   // handy for poking at the dashboard from DevTools

  /* ---------------- controls ---------------- */

  function toggleChip(btn, fn) {
    btn.addEventListener('click', () => {
      const on = !btn.classList.contains('is-on');
      btn.classList.toggle('is-on', on);
      btn.setAttribute('aria-pressed', String(on));
      fn(on);
    });
  }
  toggleChip($('#rotateBtn'), on => globeView.setAutoRotate(on));
  toggleChip($('#arcsBtn'), on => globeView.setArcs(on));
  if (globeView.reducedMotion) {
    $('#rotateBtn').classList.remove('is-on');
    $('#rotateBtn').setAttribute('aria-pressed', 'false');
  }

  const dialog = $('#sourcesDialog');
  $('#sourcesBtn').addEventListener('click', () => { renderSources(Api.state); dialog.showModal(); });
  $('#sourcesClose').addEventListener('click', () => dialog.close());
  dialog.addEventListener('click', e => { if (e.target === dialog) dialog.close(); });

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape' && openCc && !dialog.open) $('#countryClose').click();
  });
})();
