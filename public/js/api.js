/* ==========================================================================
   Api — polls the data server (server.js locally, or the Worker when hosted) for each source.
   The proxy caches upstream responses, so these intervals only control how
   quickly the page notices new data; they never hit the upstream APIs directly.
   ========================================================================== */

const API_POLL_MS = {
  radar: 5 * 60 * 1000,
  abusech: 5 * 60 * 1000,
  dshield: 10 * 60 * 1000,
  ransomware: 10 * 60 * 1000,
  kev: 30 * 60 * 1000,
};

const Api = {
  state: {},          // key -> { data, fetchedAt, stale, error, loading }
  handlers: [],

  onUpdate(fn) { this.handlers.push(fn); },

  data(key) { return this.state[key]?.data || null; },

  async load(key) {
    const prev = this.state[key] || {};
    let next;
    try {
      const res = await fetch(`/api/${key}`, { cache: 'no-store' });
      const body = await res.json();
      next = {
        data: body.data ?? prev.data ?? null,
        fetchedAt: body.fetchedAt || prev.fetchedAt || null,
        stale: !!body.stale || (!body.data && !!prev.data),
        error: body.error || null,
      };
    } catch (err) {
      next = {
        data: prev.data ?? null,
        fetchedAt: prev.fetchedAt ?? null,
        stale: !!prev.data,
        error: location.protocol === 'file:'
          ? 'Page opened as a file — run `node server.js` and open http://localhost:8080'
          : `Data server unreachable (${err.message})`,
      };
    }
    this.state[key] = next;
    this.handlers.forEach(h => h(key, next));
  },

  start() {
    for (const [key, ms] of Object.entries(API_POLL_MS)) {
      this.state[key] = { data: null, loading: true };
      this.load(key);
      setInterval(() => this.load(key), ms);
    }
  },
};
