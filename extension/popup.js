/**
 * ScamShield Extension — popup.js
 * Gets the current tab URL → calls backend → renders result
 */

const API = 'http://localhost:8000/analyze';
// Local analyzer page path
const ANALYZE_PAGE = 'http://127.0.0.1:5501/frontend/analyze.html';

// ── DOM refs ───────────────────────────────────────────────────────────────
const $loading    = document.getElementById('state-loading');
const $result     = document.getElementById('state-result');
const $error      = document.getElementById('state-error');
const $urlDisplay = document.getElementById('url-display');

const $badge      = document.getElementById('status-badge');
const $statusIcon = document.getElementById('status-icon');
const $statusLbl  = document.getElementById('status-label');
const $scoreNum   = document.getElementById('score-num');
const $ringFill   = document.getElementById('ring-fill');
const $progBar    = document.getElementById('prog-bar');
const $confText   = document.getElementById('conf-text');
const $signals    = document.getElementById('signals');
const $btnReport  = document.getElementById('btn-report');

const $errorTitle = document.getElementById('error-title');
const $errorMsg   = document.getElementById('error-msg');
const $btnRetry   = document.getElementById('btn-retry');

// ── Helpers ────────────────────────────────────────────────────────────────
function showState(id) {
  ['state-loading', 'state-result', 'state-error'].forEach(s => {
    document.getElementById(s).classList.remove('active');
  });
  document.getElementById(id).classList.add('active');
}

function truncateUrl(url, maxLen = 45) {
  return url.length > maxLen ? url.slice(0, maxLen) + '…' : url;
}

function animateScore(target) {
  let current = 0;
  const step  = Math.ceil(target / 60);
  const timer = setInterval(() => {
    current = Math.min(current + step, target);
    $scoreNum.textContent = current;
    if (current >= target) clearInterval(timer);
  }, 16);
}

function animateRing(score, color) {
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  $ringFill.style.strokeDashoffset = offset;
  $ringFill.style.stroke = color;
}

// ── Render Result ──────────────────────────────────────────────────────────
function renderResult(data, rawUrl) {
  console.log('Extension API response', data);
  const { is_safe, confidence, feature_analysis } = data;
  let score = Number(data.credibility_score ?? data.score ?? 0);
  if (!Number.isFinite(score) || isNaN(score) || score === null || score === undefined) {
    score = 0;
  }
  score = Math.max(0, Math.min(100, Number(score.toFixed(2))));

  // Badge (credibility score threshold)
  const badgeSafe = score >= 85;
  $badge.className    = 'status-badge ' + (badgeSafe ? 'safe' : 'phishing');
  $statusIcon.innerHTML = badgeSafe ? '&#x1F6E1;' : '&#x26A0;';
  $statusLbl.textContent  = badgeSafe ? 'SAFE' : 'PHISHING';

  // Score-based risk status
  let riskStatus = 'High Risk';
  let riskColor = '#ff3355';
  if (score >= 85) {
    riskStatus = 'Safe';
    riskColor = '#00ff88';
  } else if (score >= 60) {
    riskStatus = 'Low Risk';
    riskColor = '#ffdd57';
  } else if (score >= 40) {
    riskStatus = 'Medium Risk';
    riskColor = '#ffb347';
  }

  const labelEl = document.querySelector('.score-label-text');
  if (labelEl) {
    labelEl.textContent = `Credibility Score · ${riskStatus}`;
    labelEl.style.color = riskColor;
  }

  // Score ring + counter
  animateScore(score);
  setTimeout(() => animateRing(score, riskColor), 100);
  $scoreNum.style.color = riskColor;

  // Progress bar
  $progBar.className = 'prog-bar safe';
  setTimeout(() => { $progBar.style.width = confidence + '%'; }, 100);

  // Confidence text
  $confText.textContent = `Model confidence: ${Number(confidence || 0).toFixed(1)}%`;

  // Signal pills — pick most relevant features
  const SIGNAL_KEYS = [
    'has_https', 'has_suspicious_kw', 'has_at',
    'is_ip_address', 'has_hyphen', 'url_entropy'
  ];
  $signals.innerHTML = '';
  SIGNAL_KEYS.forEach(key => {
    const fa = feature_analysis[key];
    if (!fa) return;
    const isBad = fa.status === 'suspicious';
    const pill  = document.createElement('span');
    pill.className = 'signal-pill ' + (isBad ? 'bad' : 'safe');
    pill.textContent = fa.label;
    $signals.appendChild(pill);
  });

  // Report button should open the local analyze.html page with URL param
  $btnReport.onclick = () => {
    const dashUrl = `${ANALYZE_PAGE}?url=${encodeURIComponent(rawUrl)}`;
    chrome.tabs.create({ url: dashUrl });
  };

  showState('state-result');
}

// ── Analyze URL ────────────────────────────────────────────────────────────
async function analyzeUrl(url) {
  $urlDisplay.textContent = truncateUrl(url);
  showState('state-loading');

  try {
    const res = await fetch(API, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ url }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    renderResult(data, url);

    // Cache last result
    chrome.storage.local.set({ lastResult: { url, data, ts: Date.now() } });

  } catch (err) {
    $errorTitle.textContent = 'Analysis Failed';
    if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
      $errorMsg.textContent = 'Cannot reach backend server.';
    } else {
      $errorMsg.textContent = err.message;
    }
    showState('state-error');
  }
}

// ── Retry Button ───────────────────────────────────────────────────────────
$btnRetry.addEventListener('click', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    if (tabs[0]?.url) analyzeUrl(tabs[0].url);
  });
});

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs[0];
    if (!tab?.url) {
      $errorMsg.textContent = 'Could not detect the current page URL.';
      showState('state-error');
      return;
    }
    const url = tab.url;
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('about:')) {
      $urlDisplay.textContent = 'Internal page';
      $errorTitle.textContent = 'Cannot Analyze';
      $errorMsg.textContent   = 'ScamShield cannot scan internal browser pages.';
      document.querySelector('.error-hint').textContent = 'Navigate to a website and try again.';
      showState('state-error');
      return;
    }
    analyzeUrl(url);
  });
});
