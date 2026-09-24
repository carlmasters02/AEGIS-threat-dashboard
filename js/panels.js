/* ==========================================================================
   Panel renderers. All text that originates from external feeds is passed
   through esc() (or set via textContent) — feed content is untrusted input.
   ========================================================================== */

const $ = (sel, root = document) => root.querySelector(sel);
const esc = s => String(s ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
/* Links from feeds are untrusted: only http(s) URLs are ever put in an href. */
function safeUrl(u) {
  try {
    const url = new URL(String(u));
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
  } catch {
    return null;
  }
}
const fmt = n => Math.round(n).toLocaleString('en-US');
const compactFmt = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 });
const compact = n => (Math.abs(n) >= 10000 ? compactFmt.format(n) : fmt(n));
const pad2 = n => String(n).padStart(2, '0');
const pct = (v, digits = 1) => `${v.toFixed(digits)}%`;

function relTime(t) {
  const ms = typeof t === 'number' ? t : Date.parse(t);
  if (!isFinite(ms)) return '—';
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function shortDate(t) {
  const d = new Date(typeof t === 'number' ? t : Date.parse(t));
  return isFinite(d) ? d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', timeZone: 'UTC' }) : '—';
}

function el(tag, cls, html) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (html != null) n.innerHTML = html;
  return n;
}

/* Tween a number inside an element. */
function tweenNumber(node, to, format = compact, ms = 700) {
  const from = node._v ?? 0;
  node._v = to;
  const t0 = performance.now();
  const step = now => {
    if (node._v !== to) return;
    const k = Math.min(1, (now - t0) / ms);
    node.textContent = format(from + (to - from) * (1 - Math.pow(1 - k, 3)));
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

/* Reorder children to match `ordered`, animating each row from its old position (FLIP). */
function flipReorder(container, ordered) {
  const before = new Map();
  for (const child of container.children) before.set(child, child.getBoundingClientRect().top);
  ordered.forEach(n => container.appendChild(n));
  for (const n of ordered) {
    const prev = before.get(n);
    if (prev == null) continue;
    const dy = prev - n.getBoundingClientRect().top;
    if (Math.abs(dy) < 1) continue;
    n.style.transition = 'none';
    n.style.transform = `translateY(${dy}px)`;
    requestAnimationFrame(() => {
      n.style.transition = 'transform 0.6s cubic-bezier(.2,.8,.2,1)';
      n.style.transform = '';
    });
  }
}

/* "▲ 12% vs prior" — up is bad (red) unless invert. */
function deltaHtml(cur, prev, { suffix = ' vs prior', invert = false } = {}) {
  if (!prev) return cur ? `<span class="up">new</span>${suffix}` : `<span>—</span>`;
  const ratio = cur / prev - 1;
  if (Math.abs(ratio) < 0.005) return `<span>— 0%</span>${suffix}`;
  const up = ratio > 0;
  const mag = ratio >= 2 ? `${(cur / prev).toFixed(cur / prev < 10 ? 1 : 0)}×` : `${Math.abs(Math.round(ratio * 100))}%`;
  return `<span class="${up !== invert ? 'up' : 'down'}">${up ? '▲' : '▼'} ${mag}</span>${suffix}`;
}

const emptyLi = msg => `<li class="empty">${esc(msg)}</li>`;

/* ------------------------------------------------------------------ KPIs */

const KPI = {
  init() {
    this.items = {};
    document.querySelectorAll('[data-kpi]').forEach(k => {
      this.items[k.dataset.kpi] = { root: k, label: $('.lbl', k), value: $('.kpi-value', k), sub: $('.kpi-sub', k) };
    });
  },

  set(key, { value, format = compact, sub = '', label, title = '' }) {
    const it = this.items[key];
    if (label) it.label.textContent = label;
    if (value == null) { it.value._v = undefined; it.value.textContent = '—'; }
    else tweenNumber(it.value, value, format);
    it.sub.innerHTML = sub;
    it.root.title = title;
  },
};

/* ------------------------------------------------------------------ Infocon */

const ThreatLevel = {
  init() {
    this.root = $('#threatLevel');
    this.value = $('#threatLevelValue');
    this.segs = [...this.root.querySelectorAll('.tl-segs i')];
  },
  render(status) {
    const lvl = INFOCON[status];
    if (!lvl) {
      this.value.textContent = status ? String(status).toUpperCase() : 'N/A';
      this.segs.forEach(s => s.classList.remove('on'));
      return;
    }
    this.root.style.setProperty('--tl', lvl.color);
    this.value.textContent = lvl.label;
    this.segs.forEach((s, i) => s.classList.toggle('on', i < lvl.step));
    this.root.title = `SANS Internet Storm Center Infocon: ${lvl.label} — ${lvl.text}`;
  },
};

/* ------------------------------------------------------------------ Ransomware leaderboard */

function sparkPaths(values, w, h) {
  if (values.length < 2) return ['', ''];
  const max = Math.max(...values, 1);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * w, h - 1 - (v / max) * (h - 3)]);
  const line = 'M' + pts.map(p => p.map(n => n.toFixed(1)).join(',')).join('L');
  return [line, `${line}L${w},${h}L0,${h}Z`];
}

const Actors = {
  init(onSelect) {
    this.list = $('#actorList');
    this.rows = new Map();
    this.onSelect = onSelect;
    this.tracked = null;
  },

  setTracked(name) {
    this.tracked = name;
    for (const [n, r] of this.rows) r.li.classList.toggle('is-tracked', n === name);
  },

  render(groups, message) {
    if (!groups || !groups.length) {
      this.rows.clear();
      this.list.innerHTML = emptyLi(message || 'No data');
      return;
    }
    this.list.querySelector('.empty')?.remove();
    const shown = groups.slice(0, 20);
    const max = shown[0].count || 1;
    const ordered = shown.map((g, i) => {
      const r = this.rows.get(g.name) || this._create(g.name);
      r.rank.textContent = pad2(i + 1);
      const where = [g.topCountry, g.topSector].filter(Boolean).join(' · ');
      r.sub.textContent = where ? `most hit: ${where}` : '—';
      tweenNumber(r.score, g.count, fmt);
      r.bar.style.width = `${(g.count / max) * 100}%`;
      r.delta.innerHTML = deltaHtml(g.count, g.prior, { suffix: '' });
      const [line, area] = sparkPaths(g.daily, 54, 20);
      r.line.setAttribute('d', line);
      r.area.setAttribute('d', area);
      r.li.title = `${g.name}: ${g.count} victims posted in the last 30 days (${g.prior} in the 30 days before). Click to map their victims.`;
      return r.li;
    });
    const keep = new Set(shown.map(g => g.name));
    for (const [n, r] of this.rows) if (!keep.has(n)) { r.li.remove(); this.rows.delete(n); }
    flipReorder(this.list, ordered);
    this.setTracked(this.tracked);
  },

  _create(name) {
    const li = el('li', 'actor');
    li.tabIndex = 0;
    li.innerHTML = `
      <span class="actor-rank"></span>
      <div class="actor-id">
        <div class="actor-name"><span></span></div>
        <div class="actor-alias"></div>
      </div>
      <svg class="spark" viewBox="0 0 54 20" preserveAspectRatio="none" aria-hidden="true"><path class="area"/><path class="line"/></svg>
      <div class="actor-score"><b></b><div class="score-bar"><i></i></div></div>
      <span class="actor-delta"></span>`;
    $('.actor-name span', li).textContent = name;
    const select = () => this.onSelect(this.tracked === name ? null : name);
    li.addEventListener('click', select);
    li.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(); } });
    const r = {
      li,
      rank: $('.actor-rank', li),
      sub: $('.actor-alias', li),
      score: $('.actor-score b', li),
      bar: $('.score-bar i', li),
      delta: $('.actor-delta', li),
      line: $('.spark .line', li),
      area: $('.spark .area', li),
    };
    this.rows.set(name, r);
    return r;
  },
};

/* ------------------------------------------------------------------ Alerts */

const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' };

const Alerts = {
  init(onFocus) {
    this.list = $('#alertList');
    this.filter = 'all';
    this.onFocus = onFocus;
    this.seen = null;
    this.countEls = {};
    document.querySelectorAll('#sevFilter [data-count]').forEach(n => { this.countEls[n.dataset.count] = n; });
    $('#sevFilter').addEventListener('click', e => {
      const btn = e.target.closest('.sev-chip');
      if (!btn) return;
      this.filter = btn.dataset.sev;
      document.querySelectorAll('#sevFilter .sev-chip').forEach(b => b.classList.toggle('is-on', b === btn));
      this._applyFilter();
    });
  },

  /* items: [{ id, sev, t, source, title, url, meta: [str], cc }] */
  render(items, message) {
    const scroll = this.list.scrollTop;
    const firstPass = this.seen === null;
    this.seen = this.seen || new Set();
    this.list.innerHTML = items.length ? '' : emptyLi(message || 'No alerts');

    for (const it of items) {
      const li = el('li', `alert sev-${it.sev}`);
      if (!firstPass && !this.seen.has(it.id)) {
        li.classList.add('fresh');
        setTimeout(() => li.classList.remove('fresh'), 1800);
      }
      this.seen.add(it.id);
      li.dataset.sev = it.sev;
      const href = safeUrl(it.url);
      const title = href
        ? `<a href="${esc(href)}" target="_blank" rel="noopener noreferrer">${esc(it.title)}</a>`
        : esc(it.title);
      const when = new Date(it.t);
      li.innerHTML = `
        <div class="alert-top"><span class="pill">${SEV_LABEL[it.sev]}</span><span class="src-tag">${esc(it.source)}</span>
          <time datetime="${when.toISOString()}" title="${when.toUTCString()}">${it.dateOnly ? shortDate(it.t) : relTime(it.t)}</time></div>
        <div class="alert-title">${title}</div>
        <div class="alert-meta">${it.meta.filter(Boolean).map(m => `<span>${esc(m)}</span>`).join('')}</div>`;
      if (it.cc) {
        li.tabIndex = 0;
        li.classList.add('has-geo');
        li.title = `Click to show ${countryName(it.cc)} on the globe`;
        li.addEventListener('click', e => { if (!e.target.closest('a')) this.onFocus(it.cc); });
        li.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.target.closest('a')) this.onFocus(it.cc); });
      }
      this.list.appendChild(li);
    }
    this._applyFilter();
    this.list.scrollTop = scroll;

    const counts = { all: items.length, critical: 0, high: 0, medium: 0, low: 0 };
    for (const it of items) counts[it.sev]++;
    for (const k in counts) this.countEls[k].textContent = counts[k];
  },

  _applyFilter() {
    for (const li of this.list.children) {
      if (li.dataset.sev) li.classList.toggle('is-hidden', this.filter !== 'all' && li.dataset.sev !== this.filter);
    }
  },
};

/* ------------------------------------------------------------------ Bar lists */

class BarList {
  constructor(list, foot, { onRowClick } = {}) {
    this.list = list;
    this.foot = foot;
    this.onRowClick = onRowClick;
    this.rows = new Map();
    this.dataset = null;
  }

  /* rows: [{ key, label, code?, value, display, side? }] */
  render(rows, { foot = '', empty = 'No data', dataset = '' } = {}) {
    if (dataset !== this.dataset) {        // switching datasets: rebuild instead of animating unrelated rows
      this.rows.clear();
      this.list.innerHTML = '';
      this.dataset = dataset;
    }
    this.foot.innerHTML = foot;
    if (!rows || !rows.length) {
      this.rows.clear();
      this.list.innerHTML = emptyLi(empty);
      return;
    }
    this.list.querySelector('.empty')?.remove();
    const max = Math.max(...rows.map(r => r.value), 0) || 1;
    const ordered = rows.map(row => {
      let r = this.rows.get(row.key);
      if (!r) {
        const li = el('li', 'bar-row');
        li.innerHTML = `<span class="bar-label">${row.code ? `<span class="code">${esc(row.code)}</span>` : ''}<span class="bar-name"></span></span>
          <div class="bar-track"><div class="bar-fill"></div></div><span class="bar-num"></span><span class="bar-pct"></span>`;
        $('.bar-name', li).textContent = row.label;
        li.title = row.label;
        if (this.onRowClick && row.code) {
          li.classList.add('clickable');
          li.tabIndex = 0;
          li.addEventListener('click', () => this.onRowClick(row.code));
          li.addEventListener('keydown', e => { if (e.key === 'Enter') this.onRowClick(row.code); });
        }
        r = { li, fill: $('.bar-fill', li), num: $('.bar-num', li), side: $('.bar-pct', li) };
        this.rows.set(row.key, r);
      }
      r.fill.style.width = `${(row.value / max) * 100}%`;
      r.num.textContent = row.display;
      r.side.textContent = row.side || '';
      return r.li;
    });
    const keep = new Set(rows.map(r => r.key));
    for (const [k, r] of this.rows) if (!keep.has(k)) { r.li.remove(); this.rows.delete(k); }
    flipReorder(this.list, ordered);
  }
}

/* ------------------------------------------------------------------ Trend chart */

class TrendChart {
  constructor(canvas, emptyEl) {
    this.canvas = canvas;
    this.emptyEl = emptyEl;
    this.ctx = canvas.getContext('2d');
    this.points = null;
    new ResizeObserver(() => { this._resize(); this.draw(); }).observe(canvas.parentElement);
    this._resize();
  }

  _resize() {
    const dpr = window.devicePixelRatio || 1;
    const { clientWidth: w, clientHeight: h } = this.canvas.parentElement;
    this.w = w; this.h = h;
    this.canvas.width = Math.max(1, w * dpr);
    this.canvas.height = Math.max(1, h * dpr);
    this.ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  /* points: [{ date, value }] */
  setSeries(points, { xFormat = shortDate, yFormat = compact } = {}) {
    this.points = points && points.length > 1 ? points : null;
    this.xFormat = xFormat;
    this.yFormat = yFormat;
    this.emptyEl.hidden = true;
    this.draw();
  }

  setEmpty(message) {
    this.points = null;
    this.emptyEl.textContent = message;
    this.emptyEl.hidden = false;
    this.draw();
  }

  draw() {
    const { ctx, w, h, points } = this;
    if (!w || !h) return;
    ctx.clearRect(0, 0, w, h);
    if (!points) return;

    const maxV = Math.max(...points.map(p => p.value)) * 1.12 || 1;
    const L = 40, R = 6, T = 8, B = 18;
    const cw = w - L - R, ch = h - T - B;
    const x = i => L + (i / (points.length - 1)) * cw;
    const y = v => T + ch - (v / maxV) * ch;

    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let k = 0; k <= 3; k++) {
      const v = (maxV / 3) * k;
      const yy = Math.round(y(v)) + 0.5;
      ctx.strokeStyle = 'rgba(150,120,255,0.1)';
      ctx.beginPath(); ctx.moveTo(L, yy); ctx.lineTo(w - R, yy); ctx.stroke();
      ctx.fillStyle = '#66628c';
      ctx.fillText(this.yFormat(v), L - 6, yy);
    }
    ctx.textBaseline = 'alphabetic';
    const ticks = [0, Math.floor((points.length - 1) / 2), points.length - 1];
    ticks.forEach((i, n) => {
      ctx.textAlign = n === 0 ? 'left' : n === 2 ? 'right' : 'center';
      ctx.fillText(this.xFormat(points[i].date), x(i), h - 4);
    });

    const grad = ctx.createLinearGradient(0, T, 0, T + ch);
    grad.addColorStop(0, 'rgba(199,125,255,0.45)');
    grad.addColorStop(1, 'rgba(161,0,255,0.03)');
    ctx.beginPath();
    ctx.moveTo(x(0), y(0));
    points.forEach((p, i) => ctx.lineTo(x(i), y(p.value)));
    ctx.lineTo(x(points.length - 1), y(0));
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    ctx.beginPath();
    points.forEach((p, i) => ctx[i ? 'lineTo' : 'moveTo'](x(i), y(p.value)));
    ctx.strokeStyle = '#c77dff';
    ctx.lineWidth = 1.6;
    ctx.stroke();

    const last = points[points.length - 1];
    ctx.fillStyle = '#fff';
    ctx.beginPath(); ctx.arc(x(points.length - 1), y(last.value), 2.5, 0, Math.PI * 2); ctx.fill();
  }
}

/* ------------------------------------------------------------------ KEV table */

const Kev = {
  init() { this.body = $('#cveBody'); this.meta = $('#kevMeta'); },
  render(kev, message) {
    if (!kev) {
      this.body.innerHTML = `<tr><td colspan="4" class="empty">${esc(message || 'No data')}</td></tr>`;
      return;
    }
    this.meta.textContent = `${fmt(kev.total)} total · catalog ${kev.catalogVersion}`;
    this.body.innerHTML = kev.recent.slice(0, 20).map(v => {
      const e = v.epss;
      const heat = e && e.percentile >= 0.95 ? 'hot' : e && e.percentile >= 0.8 ? 'warm' : '';
      const epss = e
        ? `<span class="epss ${heat}" title="EPSS ${(e.score * 100).toFixed(2)}% · ${Math.round(e.percentile * 100)}th percentile (${esc(e.date)})">${(e.score * 100).toFixed(1)}%</span>`
        : '<span class="dim">n/a</span>';
      return `<tr title="${esc(v.name)} — ${esc(v.description)}">
        <td><a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}" target="_blank" rel="noopener noreferrer">${esc(v.cve)}</a>${v.ransomware ? ' <span class="rw-flag" title="Known use in ransomware campaigns">R</span>' : ''}</td>
        <td>${esc(v.vendor)} · ${esc(v.product)}</td>
        <td>${shortDate(v.dateAdded)}</td>
        <td>${epss}</td></tr>`;
    }).join('');
  },
};

/* ------------------------------------------------------------------ Stream (URLhaus) */

const Stream = {
  init() { this.list = $('#streamList'); this.seen = new Set(); },
  render(latest, message) {
    if (!latest || !latest.length) { this.list.innerHTML = emptyLi(message || 'No data'); return; }
    this.list.innerHTML = latest.slice(0, 6).map(u => {
      const d = new Date(u.added);
      const fresh = this.seen.size && !this.seen.has(u.id) ? ' class="fresh"' : '';
      const tag = u.tags[0] || u.threat;
      const href = safeUrl(u.link);
      const host = href
        ? `<a class="route" href="${esc(href)}" target="_blank" rel="noopener noreferrer" title="${esc(u.host)} (defanged) · ${esc(u.status)}">${esc(u.host)}</a>`
        : `<span class="route">${esc(u.host)}</span>`;
      return `<li${fresh} style="--c:${u.status === 'online' ? 'var(--crit)' : 'var(--dim)'}">
        <span>${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}Z</span>${host}<span class="sev">${esc(tag)}</span></li>`;
    }).join('');
    latest.forEach(u => this.seen.add(u.id));
  },
};

/* ------------------------------------------------------------------ Intel ticker */

const Ticker = {
  init() {
    this.track = $('#tickerTrack');
    this.viewport = this.track.parentElement;
    this.offset = 0;
    this.queue = [];
    this.keys = new Set();
    this.speed = 45; // px / s
    let last = performance.now();
    const loop = now => {
      const dt = Math.min(0.1, (now - last) / 1000);
      last = now;
      this._step(dt);
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  },

  /* html must already be escaped. Items with a key are only ever queued once. */
  push(html, color, key) {
    if (key) {
      if (this.keys.has(key)) return;
      this.keys.add(key);
    }
    const span = el('span', 'ticker-item', html);
    if (color) span.style.setProperty('--c', color);
    this.queue.push(span);
    if (this.queue.length > 30) this.queue.shift();
  },

  _step(dt) {
    const vw = this.viewport.clientWidth;
    while (this.queue.length && this.track.scrollWidth - this.offset < vw * 1.5) {
      this.track.appendChild(this.queue.shift());
    }
    this.offset += this.speed * dt;
    const first = this.track.firstElementChild;
    if (first && first.offsetWidth <= this.offset) {
      this.offset -= first.offsetWidth;
      first.remove();
      if (this.queue.length < 2) this.track.appendChild(first);   // recycle when no fresh intel is waiting
    }
    if (!this.track.firstElementChild) this.offset = 0;
    this.track.style.transform = `translateX(${-this.offset}px)`;
  },
};

/* ------------------------------------------------------------------ Clocks */

function startClocks() {
  const u = $('#clockUtc'), l = $('#clockLocal');
  const tick = () => {
    const d = new Date();
    u.textContent = `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())}`;
    l.textContent = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  };
  tick();
  setInterval(tick, 1000);
}

/* ------------------------------------------------------------------ Sources dialog */

function sourceStatus(key, st) {
  if (!st || st.loading) return { cls: 'loading', text: 'Loading…' };
  if (key === 'radar' && st.data && st.data.configured === false) {
    return { cls: 'off', text: 'Not configured — add CLOUDFLARE_API_TOKEN to .env (free token, "Radar: Read")' };
  }
  if (st.data && st.error) return { cls: 'stale', text: `Serving cached data — ${st.error}` };
  if (st.data) {
    const failed = key === 'radar' && st.data.errors ? Object.keys(st.data.errors).length : 0;
    return failed
      ? { cls: 'stale', text: `Partially available (${failed} endpoints failed) · updated ${relTime(st.fetchedAt)}` }
      : { cls: 'ok', text: `Updated ${relTime(st.fetchedAt)}` };
  }
  return { cls: 'error', text: st.error || 'Unavailable' };
}

function renderSources(state) {
  $('#sourcesList').innerHTML = Object.entries(SOURCES).map(([key, s]) => {
    const st = sourceStatus(key, state[key]);
    return `<li class="src src-${st.cls}">
      <div class="src-head"><span class="src-dot"></span><a href="${esc(s.url)}" target="_blank" rel="noopener noreferrer">${esc(s.name)}</a>
        <span class="src-license">${esc(s.license)}</span></div>
      <p>${esc(s.what)}</p>
      <div class="src-status">${esc(st.text)}</div></li>`;
  }).join('');
}
