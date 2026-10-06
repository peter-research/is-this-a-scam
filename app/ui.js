/* UI controller — shared by Electron and the Android WebView. */

const COLORS = {
  safe: '#2ea043', likely_safe: '#3fb950', caution: '#d29922',
  risky: '#f0883e', danger: '#f85149', unknown: '#8b949e',
};
const CIRC = 364.4; // 2 * pi * 58

const $ = id => document.getElementById(id);
const form = $('form'), input = $('q'), go = $('go'), hint = $('hint');
const result = $('result'), errBox = $('err');

let busy = false;

/* Rotating hints while a check runs — a check takes a few seconds. */
const STEPS = [
  'Asking ScamAdviser…',
  'Checking domain age…',
  'Scanning phishing feeds…',
  'Looking up DNS records…',
  'Checking the archive…',
];
let stepTimer = null;

function startHints() {
  let i = 0;
  hint.textContent = STEPS[0];
  stepTimer = setInterval(() => {
    i = (i + 1) % STEPS.length;
    hint.textContent = STEPS[i];
  }, 1400);
}
function stopHints() {
  clearInterval(stepTimer);
  stepTimer = null;
}

function showError(msg) {
  errBox.textContent = msg;
  errBox.classList.add('on');
  result.classList.remove('on');
}

function scoreColor(key) { return COLORS[key] || COLORS.unknown; }

function render(report) {
  const color = scoreColor(report.verdictKey);

  // ring
  const bar = $('bar');
  bar.style.stroke = color;
  const offset = CIRC * (1 - report.score / 100);
  bar.style.strokeDashoffset = CIRC;           // reset for the animation
  requestAnimationFrame(() => { bar.style.strokeDashoffset = offset; });

  $('score').textContent = report.score;
  $('score').style.color = color;
  $('verdict').textContent = report.verdict;
  $('verdict').style.color = color;
  $('domain').textContent = report.domain;
  $('summary').textContent = report.summary;

  // per-source breakdown
  const box = $('sources');
  box.innerHTML = '';
  for (const s of report.sources) {
    const row = document.createElement('div');
    row.className = 'src' + (s.ok ? '' : ' off');

    const dot = document.createElement('span');
    dot.className = 'dot';
    dot.style.background = s.ok ? scoreColor(s.score >= 70 ? 'safe'
      : s.score >= 50 ? 'caution' : s.score >= 30 ? 'risky' : 'danger') : '#3a424c';

    const nm = document.createElement('span');
    nm.className = 'nm';
    nm.textContent = s.name;

    const dt = document.createElement('span');
    dt.className = 'dt';
    dt.textContent = s.detail;

    const sc = document.createElement('span');
    sc.className = 'sc';
    if (s.ok && s.score !== null) {
      sc.textContent = Math.round(s.score);
      sc.style.color = dot.style.background;
    } else {
      sc.textContent = '—';
      sc.style.color = '#5b6470';
    }

    row.append(dot, nm, dt, sc);
    box.appendChild(row);
  }

  $('timing').textContent = `${report.sources.filter(s => s.ok).length}/${report.sources.length} sources · ${report.elapsedMs} ms`;
  $('stamp').textContent = report.checkedAt;

  // Show how the score was actually reached — weighted mean of the sources
  // that answered, so an unavailable source is never silently a zero.
  const live = report.sources.filter(s => s.ok && s.score !== null);
  const why = $('why');
  if (live.length) {
    const tw = live.reduce((a, s) => a + s.weight, 0);
    const parts = live
      .slice()
      .sort((a, b) => b.weight - a.weight)
      .map(s => `${s.name} ${Math.round(s.score)}×${s.weight.toFixed(2)}`)
      .join(' + ');
    why.textContent = `Weighted from ${live.length} source${live.length > 1 ? 's' : ''}: ${parts} ÷ ${tw.toFixed(2)}`;
  } else {
    why.textContent = '';
  }

  result.classList.add('on');
}

async function run(target) {
  if (busy) return;
  const t = (target ?? input.value).trim();
  if (!t) { input.focus(); return; }

  busy = true;
  go.disabled = true;
  go.innerHTML = '<span class="spin"></span>Checking';
  errBox.classList.remove('on');
  result.classList.remove('on');
  startHints();

  try {
    const report = await analyze(t);
    stopHints();
    hint.textContent = '';
    render(report);
  } catch (e) {
    stopHints();
    hint.textContent = '';
    showError(e && e.message ? e.message : 'Something went wrong. Check your connection.');
  } finally {
    busy = false;
    go.disabled = false;
    go.textContent = 'Check';
  }
}

form.addEventListener('submit', ev => { ev.preventDefault(); run(); });

/* Deep-link support: index.html?q=example.com (used by the Android share intent). */
(function boot() {
  // Point core.js at the native transport of whichever shell we are running in.
  if (location.protocol === 'https:' && location.hostname === 'app.local') {
    window.__ANDROID_PROXY = 'https://app.local/proxy?u=';
  }
  const q = new URLSearchParams(location.search).get('q');
  if (q) { input.value = q; run(q); } else { input.focus(); }
})();
