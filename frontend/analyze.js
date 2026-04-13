/**
 * ScamShield Dashboard â€” app.js
 * Reads ?url=... from query params â†’ calls backend â†’ renders full analysis
 */

const API_BASE = 'http://localhost:8000';

// â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const $ = id => document.getElementById(id);
const show = id => { const el = $(id); if (el) el.classList.remove('hidden'); };
const hide = id => { const el = $(id); if (el) el.classList.add('hidden'); };

function getUrlParam() {
  return new URLSearchParams(window.location.search).get('url') || '';
}

function parseUrl(raw) {
  try {
    const u = new URL(raw.startsWith('http') ? raw : 'http://' + raw);
    return { protocol: u.protocol.replace(':', '').toUpperCase(), hostname: u.hostname, pathname: u.pathname, search: u.search };
  } catch { return { protocol: '?', hostname: raw, pathname: '', search: '' }; }
}

function animateCounter(el, target, duration = 1200) {
  const start = performance.now();
  const update = now => {
    const pct = Math.min((now - start) / duration, 1);
    const ease = 1 - Math.pow(1 - pct, 3);
    el.textContent = Math.round(ease * target);
    if (pct < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

function setLoadingStep(idx) {
  document.querySelectorAll('.step').forEach((el, i) => {
    el.classList.toggle('active', i === idx);
    el.classList.toggle('done', i < idx);
  });
}

// â”€â”€ Canvas Gauge (semicircle) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function drawGauge(score, statusColor) {
  const canvas = $('gauge-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const cx = 100, cy = 100, r = 80;
  const startAngle = Math.PI;
  const endAngle = 2 * Math.PI;
  const fillAngle = startAngle + (score / 100) * Math.PI;

  ctx.clearRect(0, 0, 200, 110);

  // Track
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = 'rgba(255,255,255,0.06)';
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();

  const colorMap = {
    green: { main: '#00ff88', dark: '#00cc66', glow: 'rgba(0,255,136,0.25)' },
    yellow: { main: '#ffdd57', dark: '#e6c000', glow: 'rgba(255,221,87,0.25)' },
    orange: { main: '#ffb347', dark: '#ff8c00', glow: 'rgba(255,179,71,0.25)' },
    red: { main: '#ff3355', dark: '#cc1133', glow: 'rgba(255,51,85,0.25)' },
  };
  const c = colorMap[statusColor] || colorMap.red;

  // Fill
  const grad = ctx.createLinearGradient(cx - r, 0, cx + r, 0);
  grad.addColorStop(0, c.dark);
  grad.addColorStop(1, c.main);
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, fillAngle);
  ctx.strokeStyle = grad;
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Glow
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, fillAngle);
  ctx.strokeStyle = c.glow;
  ctx.lineWidth = 22;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Tick marks
  for (let i = 0; i <= 10; i++) {
    const angle = Math.PI + (i / 10) * Math.PI;
    const x1 = cx + (r - 9) * Math.cos(angle);
    const y1 = cy + (r - 9) * Math.sin(angle);
    const x2 = cx + (r - 16) * Math.cos(angle);
    const y2 = cy + (r - 16) * Math.sin(angle);
    ctx.beginPath();
    ctx.moveTo(x1, y1); ctx.lineTo(x2, y2);
    ctx.strokeStyle = 'rgba(255,255,255,0.15)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }
}

// Animate gauge from 0 to target score
function animateGauge(score, statusColor) {
  let current = 0;
  const timer = setInterval(() => {
    current = Math.min(current + 2, score);
    drawGauge(current, statusColor);
    if (current >= score) clearInterval(timer);
  }, 20);
}

// â”€â”€ Donut Chart â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let donutChart = null;
function renderDonut(safePct, phishPct) {
  safePct = Number.isFinite(safePct) ? Math.max(0, Math.min(100, safePct)) : 0;
  phishPct = Number.isFinite(phishPct) ? Math.max(0, Math.min(100, phishPct)) : 100;

  const ctx = $('donut-chart').getContext('2d');
  if (donutChart) donutChart.destroy();
  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Safe', 'Phishing Risk'],
      datasets: [{
        data: [safePct, phishPct],
        backgroundColor: ['rgba(0,255,136,0.85)', 'rgba(255,51,85,0.85)'],
        borderColor: ['#00ff88', '#ff3355'],
        borderWidth: 2,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed.toFixed(1)}%` }
        }
      },
      cutout: '72%',
      animation: { animateRotate: true, duration: 1200 },
    },
  });

  // Legend
  $('chart-legend').innerHTML = `
    <div class="legend-item"><span class="legend-dot" style="background:#00ff88"></span>Safe (${safePct.toFixed(1)}%)</div>
    <div class="legend-item"><span class="legend-dot" style="background:#ff3355"></span>Phishing Risk (${phishPct.toFixed(1)}%)</div>
  `;
}

// â”€â”€ Feature Cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const FEAT_ICONS = {
  url_length: 'LEN',
  num_dots: 'DOTS',
  has_at: '@',
  has_hyphen: '-',
  has_suspicious_kw: 'KEY',
  url_entropy: 'ENT',
  is_ip_address: 'IP',
  domain_length: 'DOM',
  has_https: 'TLS',
};

function renderFeatures(featureAnalysis) {
  const grid = $('feature-grid');
  grid.innerHTML = '';
  Object.entries(featureAnalysis).forEach(([key, fa], idx) => {
    const isSafe = fa.status === 'safe';
    const isUnknown = fa.status === 'unknown';
    const icon = FEAT_ICONS[key] || '•';

    let displayValue = fa.value;
    if (typeof fa.value === 'boolean') displayValue = fa.value ? 'YES' : 'NO';
    else if (typeof fa.value === 'number') displayValue = Number.isInteger(fa.value) ? fa.value : fa.value.toFixed(2);
    // strings (like formatted domain age "4 yr 3 mo") pass through as-is

    let statusLabel = isSafe ? 'Safe' : (isUnknown ? 'N/A' : 'Risk');

    const card = document.createElement('div');
    card.className = `feature-card ${fa.status}`;
    card.style.animationDelay = `${idx * 60}ms`;
    card.innerHTML = `
      <div class="feat-top">
        <span class="feat-name">${fa.label}</span>
        <span class="feat-status ${fa.status}">${statusLabel}</span>
      </div>
      <div class="feat-value ${fa.status}">${displayValue}</div>
      <p class="feat-explain">${fa.explanation}</p>
    `;
    grid.appendChild(card);
  });
}

// â”€â”€ Signal Bars â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function renderSignalBars(featureAnalysis) {
  const container = $('signal-bars');
  container.innerHTML = '';

  if (!featureAnalysis || typeof featureAnalysis !== 'object') {
    container.innerHTML = '<p class="signal-empty">No feature signals available.</p>';
    return;
  }

  let idx = 0;
  Object.keys(featureAnalysis).forEach(key => {
    const fa = featureAnalysis[key];
    if (!fa) return;
    const isSafe = String(fa.status || '').toLowerCase() === 'safe';
    const width = isSafe ? 100 : 40;
    const row = document.createElement('div');
    row.className = 'signal-row';
    row.style.animationDelay = `${idx * 50}ms`;
    row.innerHTML = `
      <span class="signal-name">${fa.label}</span>
      <div class="signal-track">
        <div class="signal-fill ${isSafe ? 'safe' : 'phishing'}" style="width:${width}%"></div>
      </div>
      <span class="signal-val">${isSafe ? '\u2714' : '\u2716'}</span>
    `;
    container.appendChild(row);
    idx += 1;
  });
}

// â”€â”€ Tech Details â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function renderTechDetails(url, features, parsed) {
  const grid = $('tech-grid');
  const items = [
    { key: 'Protocol', val: parsed.protocol },
    { key: 'Domain', val: parsed.hostname },
    { key: 'Path', val: parsed.pathname || '/' },
    { key: 'Query String', val: parsed.search || 'None' },
    { key: 'URL Length', val: features.url_length + ' chars' },
    { key: 'Entropy Score', val: features.url_entropy },
  ];
  grid.innerHTML = items.map((item, idx) => `
    <div class="tech-item" style="animation-delay:${idx * 60}ms">
      <div class="tech-key">${item.key}</div>
      <div class="tech-val">${item.val}</div>
    </div>`
  ).join('');
}

// â”€â”€ Main Render â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function renderDashboard(data) {
  console.log('Backend API response', data);
  const { url, is_safe, confidence, phish_probability, safe_probability,
    model_used, response_time_ms, features, feature_analysis } = data;

  let score = Number(data.credibility_score ?? data.score ?? 0);
  if (!Number.isFinite(score) || isNaN(score) || score === null || score === undefined) {
    score = 0;
  }
  score = Math.max(0, Math.min(100, score));
  score = Number(score.toFixed(2));

  const isSafe = Boolean(is_safe);
  const parsed = parseUrl(url);
  const safePct = score;
  const phishPct = Number((100 - score).toFixed(2));

  console.log('visual analytics input:', {
    credibility_score: score,
    safePct,
    phishPct,
    featureAnalysis: feature_analysis,
  });

  // Nav Home button (right-side)
  const $navBadge = $('nav-badge');
  $navBadge.className = 'nav-badge';
  $navBadge.innerHTML = '<a class="nav-home" href="index.html">Home</a>';

  // URL card
  $('url-value').textContent = url;
  $('url-protocol').textContent = parsed.protocol;
  $('url-domain').textContent = parsed.hostname;
  $('url-protocol').className = 'tag ' + (parsed.protocol === 'HTTPS' ? 'tag-green' : 'tag-red');

  // Verdict card (based on credibility_score)
  const verdictSafe = score >= 85;
  $('verdict-badge').className = 'verdict-badge ' + (verdictSafe ? 'safe' : 'phishing');
  $('verdict-icon').innerHTML = verdictSafe ? '&#x1F6E1;' : '&#x26A0;';
  $('verdict-label').textContent = verdictSafe ? 'SAFE' : 'PHISHING';
  $('verdict-desc').textContent = isSafe
    ? 'Warning: This URL shows signs of phishing. Exercise extreme caution before proceeding.'
    : 'This URL appears to be legitimate. No phishing indicators detected by the AI model.';
  $('response-time').textContent = `Analyzed in ${response_time_ms}ms Â· Model: ${model_used}`;

  // Gauge and risk status (based on credibility score, not model classification)
  let scoreStatus;
  let scoreColorName;
  let scoreColorHex;

  let riskClass;

  if (score >= 85) {
    scoreStatus = 'Safe';
    scoreColorName = 'green';
    scoreColorHex = '#00ff88';
    riskClass = 'safe';
  } else if (score >= 60) {
    scoreStatus = 'Low Risk';
    scoreColorName = 'yellow';
    scoreColorHex = '#ffdd57';
    riskClass = 'low';
  } else if (score >= 40) {
    scoreStatus = 'Medium Risk';
    scoreColorName = 'orange';
    scoreColorHex = '#ffb347';
    riskClass = 'medium';
  } else {
    scoreStatus = 'High Risk';
    scoreColorName = 'red';
    scoreColorHex = '#ff3355';
    riskClass = 'high';
  }

  animateGauge(score, scoreColorName);
  animateCounter($('gauge-num'), score);
  $('gauge-num').style.color = scoreColorHex;
  $('gauge-legend').textContent = scoreStatus;
  $('gauge-legend').style.color = scoreColorHex;

  // Risk label
  $('risk-level').textContent = scoreStatus;
  $('risk-level').className = 'risk-level ' + riskClass;

  // Confidence card (always green, regardless of is_safe/confidence)
  const confPct = Math.round(Number(confidence) || 0);
  $('conf-big').textContent = confPct + '%';
  $('conf-big').style.color = '#00ff88';
  $('conf-model').innerHTML = `
    <span class="conf-model-text">${model_used}</span>
    <span class="conf-model-status">Safe</span>
  `;
  const confBar = $('conf-bar');
  confBar.className = 'conf-bar safe';
  setTimeout(() => {
    confBar.style.width = confPct + '%';
    confBar.style.transition = 'width 1.4s ease-out';
  }, 200);

  // risk set above based on credibility score, so no further mapping needed here

  // Sections
  renderFeatures(feature_analysis);
  renderDonut(safePct, phishPct);
  renderSignalBars(feature_analysis);
  renderTechDetails(url, features, parsed);

  // Show page
  hide('loading-overlay');
  show('main-content');
}

// â”€â”€ Show Error â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function showError(title, msg) {
  hide('loading-overlay');
  $('err-title').textContent = title;
  $('err-msg').textContent = msg;
  show('error-page');
}

// â”€â”€ Fetch & Analyze â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function analyzeUrl(url) {
  show('main-content');
  show('loading-overlay');
  hide('error-page');

  setTimeout(() => setLoadingStep(1), 400);
  setTimeout(() => setLoadingStep(2), 900);

  try {
    const res = await fetch(`${API_BASE}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
      throw new Error(err.detail);
    }
    const data = await res.json();
    renderDashboard(data);
  } catch (err) {
    let msg = err.message;
    if (msg.includes('fetch') || msg.includes('NetworkError') || msg.includes('Failed')) {
      msg = 'Cannot reach the ScamShield backend on port 8000.';
    }
    showError('Analysis Failed', msg);
  }
}

// â”€â”€ Search Form â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
document.getElementById('search-form')?.addEventListener('submit', e => {
  e.preventDefault();
  const url = $('url-input').value.trim();
  if (url) {
    hide('search-section');
    analyzeUrl(url);
  }
});

// â”€â”€ Init â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
window.addEventListener('DOMContentLoaded', () => {
  const url = getUrlParam();
  if (url) {
    hide('search-section');
    hide('empty-state');
    hide('error-page');
    show('loading-overlay');
    analyzeUrl(decodeURIComponent(url));
  } else {
    if ($('search-section')) {
      show('search-section');
      hide('main-content');
      hide('empty-state');
      hide('error-page');
      hide('loading-overlay');
    }
    if ($('empty-state')) {
      show('empty-state');
      hide('main-content');
      hide('loading-overlay');
      hide('error-page');
    }
  }
});

