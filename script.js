/**
 * DNS SHIELD NEPAL — UI Controller + AI Integration (script.js)
 * =============================================================
 * Handles: UI rendering, gauge animation, tab switching,
 *          Anthropic API calls for AI deep analysis, report form
 */

// ═══════════════════════════════════════
//  GAUGE DRAWING (Canvas-based)
// ═══════════════════════════════════════

function drawGauge(canvas, score) {
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h);

  const cx = w / 2, cy = h - 10;
  const r = 75;
  const startAngle = Math.PI;
  const endAngle = 2 * Math.PI;

  // Background arc
  ctx.beginPath();
  ctx.arc(cx, cy, r, startAngle, endAngle);
  ctx.strokeStyle = 'rgba(255,255,255,0.1)';
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Colored score arc
  const grad = ctx.createLinearGradient(cx - r, cy, cx + r, cy);
  grad.addColorStop(0, '#00e676');
  grad.addColorStop(0.5, '#ffd32a');
  grad.addColorStop(1, '#ff4757');
  ctx.beginPath();
  const scoreAngle = startAngle + (score / 100) * Math.PI;
  ctx.arc(cx, cy, r, startAngle, scoreAngle);
  ctx.strokeStyle = grad;
  ctx.lineWidth = 14;
  ctx.lineCap = 'round';
  ctx.stroke();

  // Needle
  const needleAngle = Math.PI + (score / 100) * Math.PI;
  const nx = cx + Math.cos(needleAngle) * (r - 18);
  const ny = cy + Math.sin(needleAngle) * (r - 18);
  ctx.beginPath();
  ctx.moveTo(cx, cy);
  ctx.lineTo(nx, ny);
  ctx.strokeStyle = 'white';
  ctx.lineWidth = 2.5;
  ctx.lineCap = 'round';
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(cx, cy, 5, 0, 2 * Math.PI);
  ctx.fillStyle = 'white';
  ctx.fill();
}

// ═══════════════════════════════════════
//  UI HELPERS
// ═══════════════════════════════════════

function setDomain(d) {
  document.getElementById('domainInput').value = d;
  document.getElementById('domainInput').focus();
}

function clearInput() {
  document.getElementById('domainInput').value = '';
  document.getElementById('resultsPanel').classList.add('hidden');
  document.getElementById('loadingPanel').classList.add('hidden');
}

function switchTab(name, btn) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (btn) btn.classList.add('active');
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

async function animateProgress(fillId, duration) {
  const el = document.getElementById(fillId);
  const steps = 40;
  for (let i = 0; i <= steps; i++) {
    el.style.width = (i / steps * 100) + '%';
    await delay(duration / steps);
  }
}

// ═══════════════════════════════════════
//  LOADING ANIMATION
// ═══════════════════════════════════════

async function showLoadingPhases(aiDelay = 1800) {
  document.getElementById('loadingPanel').classList.remove('hidden');
  const phases = ['lp1','lp2','lp3'];

  // Phase 1: Feature Extraction
  document.getElementById('lp1').classList.add('active');
  await animateProgress('lpf1', 600);
  document.getElementById('lp1').classList.add('done');

  // Phase 2: ML Scoring
  document.getElementById('lp2').classList.add('active');
  await animateProgress('lpf2', 500);
  document.getElementById('lp2').classList.add('done');

  // Phase 3: AI Analysis (longer)
  document.getElementById('lp3').classList.add('active');
  await animateProgress('lpf3', aiDelay);
}

// ═══════════════════════════════════════
//  ML ANALYSIS MAIN FLOW
// ═══════════════════════════════════════

let lastAnalysis = null;

async function runMLAnalysis() {
  const input = document.getElementById('domainInput').value.trim();
  if (!input) { alert('Please enter a domain name.'); return; }

  const domain = input.replace(/^https?:\/\//,'').replace(/\/.*/,'').replace(/:\d+$/,'').trim();
  if (!domain.includes('.')) { alert('Please enter a valid domain with a TLD (e.g. example.com)'); return; }

  // Reset UI
  document.getElementById('resultsPanel').classList.add('hidden');
  document.getElementById('loadingPanel').classList.remove('hidden');
  document.getElementById('btnText').textContent = 'Analyzing...';
  document.getElementById('analyzeBtn').disabled = true;

  // Reset phase state
  ['lp1','lp2','lp3'].forEach(id => {
    const el = document.getElementById(id);
    el.classList.remove('active','done');
    document.getElementById(id.replace('lp','lpf')).style.width = '0%';
  });

  // Run ML synchronously (fast) while showing animation
  const analysisPromise = Promise.resolve(analyzeDomain(domain));

  // Show loading phases in parallel
  await showLoadingPhases(1800);
  const analysis = await analysisPromise;
  lastAnalysis = analysis;

  document.getElementById('loadingPanel').classList.add('hidden');
  document.getElementById('btnText').textContent = 'Run ML Analysis';
  document.getElementById('analyzeBtn').disabled = false;

  renderResults(domain, analysis);

  // Scroll to results
  document.getElementById('resultsPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ═══════════════════════════════════════
//  RENDER RESULTS
// ═══════════════════════════════════════

function renderResults(domain, analysis) {
  const { features, score, contributions, modules, riskLevel } = analysis;

  document.getElementById('resultsPanel').classList.remove('hidden');

  // Gauge
  const canvas = document.getElementById('gaugeCanvas');
  let animScore = 0;
  const gaugeInterval = setInterval(() => {
    animScore = Math.min(score, animScore + Math.ceil(score / 30));
    drawGauge(canvas, animScore);
    document.getElementById('gaugeScoreLabel').textContent = animScore;
    if (animScore >= score) clearInterval(gaugeInterval);
  }, 30);

  // Risk badge
  const badge = document.getElementById('riskBadge');
  const badgeMap = {
    danger:  ['🚨 HIGH RISK',    'danger'],
    warning: ['⚠️ SUSPICIOUS',   'warning'],
    safe:    ['✅ SAFE',         'safe'],
  };
  const [label, cls] = badgeMap[riskLevel] || ['UNKNOWN',''];
  badge.textContent = label;
  badge.className = 'risk-badge ' + cls;

  document.getElementById('domainDisplay').textContent = domain;

  // Summary line
  const flaggedModules = Object.values(modules).filter(m => m.flag === 'fail').length;
  const warnModules = Object.values(modules).filter(m => m.flag === 'warn').length;
  let summaryLine = features._isWhitelisted
    ? 'Verified safe domain — in trusted whitelist'
    : `ML Risk Score: ${score}/100 · ${flaggedModules} flagged · ${warnModules} warnings · ${Object.keys(features).filter(k=>!k.startsWith('_')).length} features analyzed`;
  document.getElementById('threatSummaryLine').textContent = summaryLine;

  // Top flags
  const flagsEl = document.getElementById('topFlags');
  const topFlags = [];
  if (features.tldAbuseScore > 0.6) topFlags.push(`${features._tld} TLD (${Math.round(features.tldAbuseScore*100)}% abuse rate)`);
  if (features._matchedBrands.length > 0) topFlags.push(`Brand: ${features._matchedBrands[0]}`);
  if (features._foundKeywords.length > 0) topFlags.push(`Keywords: ${features._foundKeywords.slice(0,3).join(', ')}`);
  if (features.typosquatScore > 0.5) topFlags.push(`Typosquat of "${features._closestBrand}"`);
  flagsEl.innerHTML = topFlags.map(f => `<span class="flag-pill">${f}</span>`).join('');

  // Render tabs
  renderFeaturesTab(features, contributions);
  renderDetectionsTab(modules, features);
  renderAITab(domain, features, modules, score);

  // Default to features tab
  switchTab('features', document.querySelector('[data-tab="features"]'));
}

// ═══════════════════════════════════════
//  TAB: ML FEATURES
// ═══════════════════════════════════════

function renderFeaturesTab(features, contributions) {
  const grid = document.getElementById('featuresGrid');
  grid.innerHTML = '';

  for (const [fname, meta] of Object.entries(FEATURE_DISPLAY)) {
    const val = features[fname];
    if (val === undefined) continue;
    const isGood = meta.good(val);
    const contrib = contributions[fname] || 0;
    const card = document.createElement('div');
    card.className = `feat-card ${isGood ? 'feat-good' : (contrib > 5 ? 'feat-bad' : 'feat-warn')}`;
    card.innerHTML = `
      <div class="feat-icon">${meta.icon}</div>
      <div class="feat-info">
        <div class="feat-label">${meta.label}</div>
        <div class="feat-value">${meta.format(val)}</div>
        <div class="feat-weight">ML weight: ${FEATURE_WEIGHTS[fname]?.weight ?? '—'} · Contrib: +${contrib.toFixed(1)}</div>
      </div>
      <div class="feat-status">${isGood ? '✅' : (contrib > 5 ? '🚨' : '⚠️')}</div>
    `;
    grid.appendChild(card);
  }

  // Weight chart
  renderWeightChart(contributions);
}

function renderWeightChart(contributions) {
  const chart = document.getElementById('weightChart');
  // Top 8 contributing features
  const sorted = Object.entries(contributions)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  const max = sorted[0]?.[1] || 1;

  chart.innerHTML = sorted.map(([fname, val]) => {
    const pct = Math.round((val / max) * 100);
    const display = FEATURE_DISPLAY[fname];
    return `
      <div class="wc-row">
        <div class="wc-label">${display?.icon ?? ''} ${display?.label ?? fname}</div>
        <div class="wc-bar-wrap">
          <div class="wc-bar" style="width:${pct}%"></div>
        </div>
        <div class="wc-val">+${val.toFixed(1)}</div>
      </div>
    `;
  }).join('');
}

// ═══════════════════════════════════════
//  TAB: DETECTIONS
// ═══════════════════════════════════════

function renderDetectionsTab(modules, features) {
  const list = document.getElementById('detectionsList');
  const moduleInfo = {
    phishing:   { title: 'Phishing Detection',          desc: 'Keyword-weighted scoring against phishing vocabulary' },
    malwareDGA: { title: 'Malware / DGA Detection',     desc: 'Entropy + digit ratio + consonant cluster analysis' },
    tld:        { title: 'TLD Abuse Score',              desc: 'TLD abuse probability from Spamhaus/SURBL databases' },
    brand:      { title: 'Nepali Brand Impersonation',  desc: 'Checks against 30+ Nepali brands and institutions' },
    typosquat:  { title: 'Typosquatting (Levenshtein)', desc: 'Edit-distance comparison to popular legitimate domains' },
    structural: { title: 'DNS Structural Analysis',     desc: 'Length, hyphens, subdomains, special characters' },
  };

  list.innerHTML = Object.entries(modules).map(([key, result]) => {
    const info = moduleInfo[key];
    const flagClass = result.flag === 'fail' ? 'det-fail' : result.flag === 'warn' ? 'det-warn' : 'det-pass';
    return `
      <div class="det-card ${flagClass}">
        <div class="det-header">
          <div class="det-title">${result.label}</div>
          <div class="det-badge ${result.flag}">${result.flag.toUpperCase()}</div>
        </div>
        <div class="det-method">${info.desc}</div>
        <div class="det-detail">${result.detail}</div>
      </div>
    `;
  }).join('');
}

// ═══════════════════════════════════════
//  TAB: AI ANALYSIS via Anthropic API
// ═══════════════════════════════════════

async function renderAITab(domain, features, modules, score) {
  document.getElementById('aiLoading').classList.remove('hidden');
  document.getElementById('aiContent').classList.add('hidden');

  document.getElementById('icannNote').innerHTML = `
    🌐 <strong>ICANN Alignment:</strong> This analysis is aligned with ICANN's five DNS abuse categories 
    (phishing, malware, spam, botnets, child safety abuse) as defined in ICANN's DNS Security Threat Mitigation Program.
    Suspicious domains can be reported to 
    <a href="https://www.icann.org/compliance/complaint" target="_blank" style="color:var(--accent)">ICANN Compliance →</a>
  `;

  // Build the prompt with all ML features
  const flaggedList = Object.entries(modules)
    .filter(([,r]) => r.flag !== 'pass')
    .map(([k,r]) => `• ${r.label}: ${r.detail}`)
    .join('\n');

  const prompt = `You are a DNS security expert and ICANN policy specialist. Analyze this domain and ML results for DNS abuse.

DOMAIN: ${domain}
ML RISK SCORE: ${score}/100
RISK LEVEL: ${score >= 45 ? 'HIGH RISK' : score >= 20 ? 'SUSPICIOUS' : 'LIKELY SAFE'}

KEY ML FEATURES EXTRACTED:
- Shannon Entropy: ${features.shannonEntropy} bits ${features.shannonEntropy > 3.5 ? '(HIGH - possible DGA)' : '(normal)'}
- Domain Length: ${features.domainLength} chars
- TLD: ${features._tld} (abuse score: ${Math.round(features.tldAbuseScore*100)}%)
- Phishing keywords found: ${features._foundKeywords.length > 0 ? features._foundKeywords.join(', ') : 'none'}
- Nepali brands matched: ${features._matchedBrands.length > 0 ? features._matchedBrands.join(', ') : 'none'}
- Typosquat: distance ${features._minEditDist} from "${features._closestBrand}"
- Digit ratio: ${(features.digitRatio*100).toFixed(1)}%
- Hyphen count: ${features.hyphenCount}
- Vowel deviation from natural: ${(features.vowelRatio*100).toFixed(1)}%

MODULE CLASSIFICATION RESULTS:
${flaggedList || '• All modules passed — no flags raised'}

CONTEXT: Nepal has 15M+ internet users. Common targets include eSewa, Khalti, Nabil Bank, NIC Asia, Ncell, and .gov.np sites.

Provide a concise threat intelligence report with:
1. **Threat Assessment** (2-3 sentences about what this domain likely is)
2. **Nepal-Specific Risk** (how this could target Nepali users specifically)
3. **ICANN Abuse Category** (which of the 5 ICANN DNS abuse types this falls under, if any)
4. **User Action** (what should a Nepali internet user do if they encounter this domain?)
5. **Confidence Level** (how confident are you in this assessment, and why?)

Keep the response focused, practical, and in plain English. No markdown headers - use the section numbers only.`;

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    const text = data.content?.find(b => b.type === 'text')?.text || 'Analysis unavailable.';

    document.getElementById('aiLoading').classList.add('hidden');
    const aiContent = document.getElementById('aiContent');
    aiContent.classList.remove('hidden');

    // Format the numbered sections nicely
    const formatted = text
      .replace(/(\d+\.\s?\*\*[^*]+\*\*)/g, match => `<div class="ai-section-header">${match.replace(/\*\*/g,'')}</div>`)
      .replace(/\n\n/g, '</p><p>')
      .replace(/\n/g, '<br/>');

    aiContent.innerHTML = `<div class="ai-report"><p>${formatted}</p></div>`;

  } catch (err) {
    document.getElementById('aiLoading').classList.add('hidden');
    const aiContent = document.getElementById('aiContent');
    aiContent.classList.remove('hidden');
    aiContent.innerHTML = `
      <div class="ai-error">
        <strong>⚠️ AI Analysis Unavailable</strong>
        <p>The Claude AI API requires an API key configured server-side. In a production deployment, this would connect to the Anthropic API to provide deep contextual threat intelligence. The ML scoring above is fully functional.</p>
        <p style="font-size:0.82rem;color:var(--text3);margin-top:0.5rem">To enable: set up a simple Express.js backend proxy with your Anthropic API key and update the fetch URL in script.js.</p>
      </div>
    `;
  }

  // Show report button for risky domains
  if (score >= 20) {
    document.getElementById('reportBtnBox').innerHTML = `
      <button class="report-flag-btn" onclick="prefillAndReport('${domain}')">
        🚨 Report "${domain}" to ICANN / Nepal Cyber Bureau
      </button>
    `;
  }
}

function prefillAndReport(domain) {
  document.getElementById('reportDomain').value = domain;
  document.querySelector('#report').scrollIntoView({ behavior: 'smooth' });
}

// ═══════════════════════════════════════
//  REPORT FORM
// ═══════════════════════════════════════

function submitReport() {
  const domain = document.getElementById('reportDomain').value.trim();
  const abuseType = document.getElementById('abuseType').value;
  if (!domain) { alert('Please enter a domain to report.'); return; }
  if (!abuseType) { alert('Please select the type of abuse.'); return; }

  // Log report (in production → POST to backend → ICANN/NTA API)
  console.log('DNS Abuse Report:', {
    domain, abuseType,
    description: document.getElementById('reportDesc').value,
    timestamp: new Date().toISOString(),
  });

  document.getElementById('reportSuccess').classList.remove('hidden');
  ['reportDomain','reportDesc'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('abuseType').value = '';
  setTimeout(() => document.getElementById('reportSuccess').classList.add('hidden'), 6000);
}

// ═══════════════════════════════════════
//  KEYBOARD SHORTCUT
// ═══════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('domainInput')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') runMLAnalysis();
  });

  document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', e => {
      const target = document.querySelector(a.getAttribute('href'));
      if (target) { e.preventDefault(); target.scrollIntoView({ behavior: 'smooth' }); }
    });
  });
});