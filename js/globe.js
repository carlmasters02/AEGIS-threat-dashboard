/* ==========================================================================
   GlobeView — 3D heatmap globe (globe.gl / three.js)
   - Country caps coloured + extruded by a real per-country metric
   - Persistent animated arcs for the top origin -> target attack corridors
   - Pulsing rings on countries hosting known botnet C2 servers
   ========================================================================== */

const WORLD_TOPOJSON = 'https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json';
const WORLD_TOPOJSON_SRI = 'sha384-yOCJ+8ShBm8UDqtAVtAvxTDDf4gXo5edxl/YG0FmVC5OTmqVLl7utuVGBDEeZWHf';   // pinned: fetch fails if the CDN file ever changes
const BASE_ALT = 0.006;

/* Heat ramp: deep indigo -> violet -> magenta -> orange -> amber */
const HEAT_STOPS = [
  [0.00, [38, 24, 92]],
  [0.30, [120, 30, 220]],
  [0.55, [190, 40, 255]],
  [0.72, [255, 45, 140]],
  [0.87, [255, 110, 40]],
  [1.00, [255, 214, 70]],
];

function heatRgb(t) {
  t = Math.max(0, Math.min(1, t));
  for (let i = 1; i < HEAT_STOPS.length; i++) {
    const [t1, c1] = HEAT_STOPS[i];
    if (t <= t1) {
      const [t0, c0] = HEAT_STOPS[i - 1];
      const k = (t - t0) / (t1 - t0);
      return c0.map((v, j) => Math.round(v + (c1[j] - v) * k));
    }
  }
  return HEAT_STOPS[HEAT_STOPS.length - 1][1];
}

function heatColor(t, alphaBoost = 0) {
  if (t <= 0) return `rgba(110, 90, 200, ${0.04 + alphaBoost})`;
  const [r, g, b] = heatRgb(t);
  return `rgba(${r}, ${g}, ${b}, ${Math.min(1, 0.2 + t * 0.55 + alphaBoost)})`;
}

class GlobeView {
  constructor(el, { onCountryClick, labelFor } = {}) {
    this.el = el;
    this.onCountryClick = onCountryClick || (() => {});
    this.labelFor = labelFor || (f => f.properties.name);
    this.hover = null;
    this.selected = null;
    this.corridors = [];
    this.showArcs = true;
    this.reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    this._resumeTimer = null;
  }

  async init() {
    const topo = await fetch(WORLD_TOPOJSON, { integrity: WORLD_TOPOJSON_SRI }).then(r => r.json());
    this.features = topojson.feature(topo, topo.objects.countries).features
      .filter(f => f.id !== '010')                         // drop Antarctica
      .map(f => Object.assign(f, { cc: A2_BY_ISO_NUM[f.id] || null, t: 0, value: 0, alt: BASE_ALT }));

    const g = new Globe(this.el, { animateIn: true })
      .backgroundColor('rgba(0,0,0,0)')
      .showAtmosphere(true)
      .atmosphereColor('#8a3dff')
      .atmosphereAltitude(0.2)

      // Dotted landmass texture
      .hexPolygonsData(this.features.filter(f => f.id !== '408'))   // KP outline makes h3 polyfill throw
      .hexPolygonResolution(3)
      .hexPolygonMargin(0.55)
      .hexPolygonUseDots(true)
      .hexPolygonAltitude(BASE_ALT + 0.002)          // above flat caps, below extruded (heated) ones
      .hexPolygonColor(() => 'rgba(160, 140, 255, 0.4)')
      .hexPolygonLabel(() => '')

      // Heat choropleth
      .polygonsData(this.features)
      .polygonsTransitionDuration(900)
      .polygonLabel(f => this.labelFor(f))
      .onPolygonHover(f => { this.hover = f; this.el.style.cursor = f ? 'pointer' : ''; this.refreshPolygons(); })
      .onPolygonClick(f => { if (f.cc) this.onCountryClick(f.cc); })

      // Attack corridors
      .arcsData([])
      .arcStartLat('sLat').arcStartLng('sLng').arcEndLat('eLat').arcEndLng('eLng')
      .arcColor('colors')
      .arcStroke('stroke')
      .arcAltitudeAutoScale(0.4)
      .arcDashLength(0.3)
      .arcDashGap(0.7)
      .arcDashInitialGap('gap')
      .arcDashAnimateTime('dur')
      .arcsTransitionDuration(800)
      .arcLabel('label')

      // Botnet C2 markers
      .ringsData([])
      .ringColor('colorFn')
      .ringMaxRadius('maxR')
      .ringPropagationSpeed(1.4)
      .ringRepeatPeriod(1400)
      .ringAltitude(0.008);

    const mat = g.globeMaterial();
    mat.color.set('#0a0b26');
    if (mat.emissive) { mat.emissive.set('#12083a'); mat.emissiveIntensity = 0.45; }
    mat.shininess = 8;

    const controls = g.controls();
    controls.autoRotate = !this.reducedMotion;
    controls.autoRotateSpeed = 0.35;
    controls.minDistance = 140;
    controls.maxDistance = 520;
    controls.addEventListener('start', () => this._pauseRotation(12000));

    g.pointOfView({ lat: 30, lng: 10, altitude: 2.35 });

    this.globe = g;
    this.refreshPolygons();

    const ro = new ResizeObserver(() => g.width(this.el.clientWidth).height(this.el.clientHeight));
    ro.observe(this.el);
  }

  refreshPolygons() {
    if (!this.globe) return;
    this.globe
      .polygonCapColor(f => heatColor(f.t, f === this.hover ? 0.12 : 0))
      .polygonSideColor(f => heatColor(f.t, -0.1))
      .polygonStrokeColor(f => f.cc && f.cc === this.selected ? 'rgba(255,255,255,0.9)'
        : f === this.hover ? 'rgba(230,215,255,0.8)' : 'rgba(190,165,255,0.28)')
      .polygonAltitude(f => f.alt + (f === this.hover ? 0.012 : 0));
  }

  /* values: { alpha2: number }. Log-scaled so mid-sized values still register. */
  setHeat(values) {
    if (!this.features) return;
    const max = Math.max(0, ...Object.values(values).filter(v => v > 0));
    const k = max * 0.05 || 1;
    for (const f of this.features) {
      const v = (f.cc && values[f.cc]) || 0;
      f.value = v;
      f.t = v > 0 && max > 0 ? Math.log1p(v / k) / Math.log1p(max / k) : 0;
      f.alt = BASE_ALT + Math.round(f.t * 12) / 12 * 0.05;
    }
    this.refreshPolygons();
  }

  /* pairs: [{ from, to, value, label }] — value is a share (%), used for thickness and speed. */
  setCorridors(pairs) {
    const max = Math.max(0, ...pairs.map(p => p.value));
    this.corridors = pairs.map((p, i) => {
      const a = countryPoint(p.from), b = countryPoint(p.to);
      if (!a || !b || p.from === p.to) return null;
      const share = max ? p.value / max : 0;
      const [r, g, bl] = heatRgb(0.45 + share * 0.55);
      return {
        sLat: a.lat, sLng: a.lng, eLat: b.lat, eLng: b.lng,
        colors: ['rgba(170, 120, 255, 0.25)', `rgba(${r}, ${g}, ${bl}, 0.95)`],
        stroke: 0.18 + share * 0.75,
        dur: 4200 - share * 2400,
        gap: (i * 0.37) % 1,
        label: p.label,
      };
    }).filter(Boolean);
    if (this.globe) this.globe.arcsData(this.showArcs ? this.corridors : []);
  }

  /* markers: [{ cc, weight 0..1 }] */
  setMarkers(markers) {
    if (!this.globe) return;
    this.globe.ringsData(markers.map(m => {
      const p = countryPoint(m.cc);
      return p && {
        lat: p.lat, lng: p.lng,
        maxR: 1.5 + m.weight * 3,
        colorFn: t => `rgba(62, 230, 255, ${Math.max(0, 1 - t)})`,
      };
    }).filter(Boolean));
  }

  focus(cc) {
    const p = countryPoint(cc);
    if (!p || !this.globe) return;
    this.selected = cc;
    this.refreshPolygons();
    this._pauseRotation(15000);
    this.globe.pointOfView({ lat: p.lat, lng: p.lng, altitude: 1.7 }, 1200);
  }

  clearSelection() {
    this.selected = null;
    this.refreshPolygons();
  }

  setAutoRotate(on) {
    this.autoRotateWanted = on;
    clearTimeout(this._resumeTimer);
    if (this.globe) this.globe.controls().autoRotate = on;
  }

  setArcs(on) {
    this.showArcs = on;
    if (this.globe) this.globe.arcsData(on ? this.corridors : []);
  }

  _pauseRotation(ms) {
    if (!this.globe) return;
    const controls = this.globe.controls();
    const wanted = this.autoRotateWanted ?? !this.reducedMotion;
    controls.autoRotate = false;
    clearTimeout(this._resumeTimer);
    if (wanted) this._resumeTimer = setTimeout(() => { controls.autoRotate = true; }, ms);
  }
}
