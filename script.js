/**
 * DNS Shield Nepal - DNS Abuse Detection Logic
 * =============================================
 * Phase 3: Detection Engine
 * 
 * This script performs client-side heuristic analysis of domains.
 * In a real production system, this would also query backend APIs
 * (Google Safe Browsing, PhishTank, SURBL, etc.)
 */

// ===== DATABASE: Known Abuse Patterns (Simulated) =====

// Phishing keywords commonly targeting Nepali users
const PHISHING_KEYWORDS = [
  'login', 'signin', 'secure', 'verify', 'update', 'account',
  'banking', 'payment', 'wallet', 'password', 'credential',
  'confirm', 'validation', 'alert', 'suspend', 'locked'
];

// Nepali brands/institutions commonly impersonated
const NEPAL_BRANDS = [
  'ncell', 'ntc', 'nepal-telecom', 'esewa', 'khalti', 'fonepay',
  'nabilbank', 'nabil', 'nicasia', 'nic-asia', 'primebank',
  'everestbank', 'himalayan-bank', 'hbl', 'citizen-bank',
  'nepal-gov', 'nagarikta', 'passport-nepal', 'election-nepal',
  'mofa-nepal', 'immigration-nepal', 'nepal-police',
  'nea', 'wlink', 'worldlink', 'subisu', 'vianet'
];

// Suspicious TLDs known for high DNS abuse rates
const SUSPICIOUS_TLDS = [
  '.tk', '.ml', '.ga', '.cf', '.gq',   // free TLDs heavily abused
  '.xyz', '.pw', '.cc', '.top', '.click',
  '.online', '.site', '.info', '.biz',
  '.icu', '.sbs', '.cyou', '.cam'
];

// TLDs considered safe
const SAFE_TLDS = [
  '.com', '.org', '.net', '.edu', '.gov',
  '.com.np', '.org.np', '.edu.np', '.gov.np', '.net.np',  // Nepali official
  '.io', '.co', '.app', '.dev'
];

// Simulated known malware domains (in reality, fetched from blocklists)
const KNOWN_MALWARE_DOMAINS = [
  'free-download-nepal.tk', 'virus-nepal.ml', 'hack-tool.xyz',
  'ncell-offer.xyz', 'nabilbank-login.tk', 'esewa-verify.ml',
  'nepal-prize.cf', 'nicasia-secure.xyz', 'free-recharge.tk'
];

// Legitimate domains (whitelist)
const KNOWN_SAFE = [
  'google.com', 'facebook.com', 'youtube.com', 'github.com',
  'nepal.gov.np', 'mof.gov.np', 'moha.gov.np', 'parliament.gov.np',
  'nta.gov.np', 'ictfoundation.org.np',
  'nabilbank.com', 'nicasiabank.com', 'esewa.com.np',
  'khalti.com', 'ncell.axiata.com', 'ntc.net.np',
  'anthropic.com', 'icann.org', 'cloudflare.com'
];

// ===== CORE DETECTION FUNCTIONS =====

/**
 * Phase 3A: Check if domain matches known malware/phishing blocklists
 */
function checkMalwareBlocklist(domain) {
  const normalized = domain.toLowerCase();
  if (KNOWN_SAFE.includes(normalized)) return { flagged: false, reason: 'Verified safe domain' };
  if (KNOWN_MALWARE_DOMAINS.includes(normalized)) return { flagged: true, reason: 'Found in known malware/phishing database' };
  return { flagged: false, reason: 'Not found in blocklists' };
}

/**
 * Phase 3B: Check for phishing keyword patterns
 */
function checkPhishingKeywords(domain) {
  const d = domain.toLowerCase();
  const found = PHISHING_KEYWORDS.filter(kw => d.includes(kw));
  if (found.length >= 2) return { flagged: true, reason: `Contains multiple phishing keywords: ${found.join(', ')}` };
  if (found.length === 1) return { flagged: 'warn', reason: `Contains suspicious keyword: ${found[0]}` };
  return { flagged: false, reason: 'No phishing keywords detected' };
}

/**
 * Phase 3C: Check for suspicious TLD
 */
function checkTLD(domain) {
  const d = domain.toLowerCase();
  for (const tld of SUSPICIOUS_TLDS) {
    if (d.endsWith(tld)) return { flagged: true, reason: `Uses high-abuse TLD: ${tld}` };
  }
  for (const tld of SAFE_TLDS) {
    if (d.endsWith(tld)) return { flagged: false, reason: `Reputable TLD: ${tld}` };
  }
  return { flagged: 'warn', reason: 'Unknown or uncommon TLD' };
}

/**
 * Phase 3D: Check for brand impersonation (Nepali context)
 */
function checkBrandImpersonation(domain) {
  const d = domain.toLowerCase().replace(/\./g, '-');
  
  // Exact match in safe list = legitimate
  if (KNOWN_SAFE.includes(domain.toLowerCase())) return { flagged: false, reason: 'Verified brand domain' };

  for (const brand of NEPAL_BRANDS) {
    if (d.includes(brand)) {
      // Check if it's the real brand domain
      const isLegit = KNOWN_SAFE.some(safe => domain.toLowerCase() === safe);
      if (!isLegit) {
        return { flagged: true, reason: `May be impersonating Nepali brand/service: "${brand}"` };
      }
    }
  }
  return { flagged: false, reason: 'No brand impersonation detected' };
}

/**
 * Phase 3E: Check for typosquatting patterns
 */
function checkTyposquatting(domain) {
  const popularDomains = [
    'google', 'facebook', 'youtube', 'gmail', 'microsoft',
    'ncell', 'ntc', 'esewa', 'khalti', 'nabilbank', 'nicasia'
  ];
  const d = domain.toLowerCase();
  const domainBase = d.split('.')[0];

  for (const popular of popularDomains) {
    if (domainBase !== popular && levenshtein(domainBase, popular) <= 2 && domainBase.length > 3) {
      return { flagged: true, reason: `Possible typosquatting of "${popular}"` };
    }
    // Double letter or number substitution
    if (domainBase.includes(popular.replace('o', '0')) || domainBase.includes(popular.replace('l', '1'))) {
      return { flagged: true, reason: `Character substitution typosquatting of "${popular}"` };
    }
  }
  return { flagged: false, reason: 'No typosquatting patterns detected' };
}

/**
 * Phase 3F: DNS Structure Analysis
 */
function checkDNSStructure(domain) {
  const d = domain.toLowerCase();
  const parts = d.split('.');
  const domainBase = parts[0];
  const issues = [];

  if (domainBase.length > 30) issues.push('Unusually long domain name');
  if ((domainBase.match(/-/g) || []).length >= 3) issues.push('Multiple hyphens (common in abuse domains)');
  if (/\d{4,}/.test(domainBase)) issues.push('Long numeric sequence in domain');
  if (parts.length > 4) issues.push('Excessive subdomains');
  if (/[^a-z0-9.-]/.test(d)) issues.push('Unusual characters in domain');

  if (issues.length >= 2) return { flagged: true, reason: issues.join('; ') };
  if (issues.length === 1) return { flagged: 'warn', reason: issues[0] };
  return { flagged: false, reason: 'Normal DNS structure' };
}

/**
 * Levenshtein Distance — measures string similarity
 * Used for typosquatting detection
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => Array.from({ length: n + 1 }, (_, j) => j === 0 ? i : i === 0 ? j : 0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) dp[i][j] = dp[i - 1][j - 1];
      else dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// ===== RISK SCORING =====

function calculateRiskScore(results) {
  let score = 0;
  const weights = { phishing: 35, malware: 40, suspTLD: 20, brandImperson: 30, typosquat: 25, dnsStructure: 15 };

  if (results.malware.flagged === true) score += weights.malware;
  if (results.phishing.flagged === true) score += weights.phishing;
  if (results.phishing.flagged === 'warn') score += weights.phishing * 0.5;
  if (results.suspTLD.flagged === true) score += weights.suspTLD;
  if (results.suspTLD.flagged === 'warn') score += weights.suspTLD * 0.4;
  if (results.brandImperson.flagged === true) score += weights.brandImperson;
  if (results.typosquat.flagged === true) score += weights.typosquat;
  if (results.dnsStructure.flagged === true) score += weights.dnsStructure;
  if (results.dnsStructure.flagged === 'warn') score += weights.dnsStructure * 0.5;

  // Known safe domains get score override
  if (KNOWN_SAFE.includes(currentDomain)) score = 0;

  return Math.min(100, Math.round(score));
}

// ===== UI CONTROLLER =====

let currentDomain = '';

function setDomain(domain) {
  document.getElementById('domainInput').value = domain;
  document.getElementById('domainInput').focus();
}

function clearInput() {
  document.getElementById('domainInput').value = '';
  document.getElementById('resultsPanel').classList.add('hidden');
  document.getElementById('loadingPanel').classList.add('hidden');
  document.getElementById('domainInput').focus();
}

function validateDomain(domain) {
  const cleaned = domain.trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\//,'');
  const pattern = /^[a-zA-Z0-9][a-zA-Z0-9-_.]{1,253}[a-zA-Z0-9]$/;
  return { valid: pattern.test(cleaned) || cleaned.includes('.'), cleaned };
}

async function checkDomain() {
  const input = document.getElementById('domainInput').value.trim();
  if (!input) { alert('Please enter a domain name to check.'); return; }

  const { valid, cleaned } = validateDomain(input);
  currentDomain = cleaned;

  if (!cleaned.includes('.')) {
    alert('Please enter a valid domain (e.g. example.com)');
    return;
  }

  // Hide results, show loading
  document.getElementById('resultsPanel').classList.add('hidden');
  document.getElementById('loadingPanel').classList.remove('hidden');

  // Simulate async scanning with step-by-step animation
  await simulateScan();

  // Run all checks
  const results = {
    phishing: checkPhishingKeywords(cleaned),
    malware: checkMalwareBlocklist(cleaned),
    suspTLD: checkTLD(cleaned),
    brandImperson: checkBrandImpersonation(cleaned),
    typosquat: checkTyposquatting(cleaned),
    dnsStructure: checkDNSStructure(cleaned)
  };

  const riskScore = calculateRiskScore(results);
  const isSafe = KNOWN_SAFE.includes(cleaned);

  // Hide loading, show results
  document.getElementById('loadingPanel').classList.add('hidden');
  document.getElementById('resultsPanel').classList.remove('hidden');

  // Render results
  renderResults(cleaned, results, riskScore, isSafe);
}

async function simulateScan() {
  const steps = ['ls1', 'ls2', 'ls3', 'ls4', 'ls5'];
  const msgs = [
    'Checking phishing databases...',
    'Analyzing TLD reputation...',
    'Scanning for brand impersonation...',
    'Checking DNS structure...',
    'Generating risk report...'
  ];

  // Reset steps
  steps.forEach((id, i) => {
    const el = document.getElementById(id);
    el.className = 'lstep';
    el.textContent = `⬜ ${msgs[i]}`;
  });

  for (let i = 0; i < steps.length; i++) {
    await delay(350);
    const el = document.getElementById(steps[i]);
    el.className = 'lstep active';
    el.textContent = `🔄 ${msgs[i]}`;
    document.getElementById('loaderText').textContent = msgs[i];
    await delay(500);
    el.className = 'lstep done';
    el.textContent = `✅ ${msgs[i]}`;
  }
  await delay(200);
}

function delay(ms) { return new Promise(res => setTimeout(res, ms)); }

function renderResults(domain, results, score, isSafe) {
  // Risk level
  let riskLevel, riskClass;
  if (isSafe || score === 0) { riskLevel = '✅ SAFE'; riskClass = 'safe'; }
  else if (score >= 40) { riskLevel = '🚨 HIGH RISK'; riskClass = 'danger'; }
  else if (score >= 20) { riskLevel = '⚠️ SUSPICIOUS'; riskClass = 'warning'; }
  else { riskLevel = '✅ LIKELY SAFE'; riskClass = 'safe'; }

  const badge = document.getElementById('riskBadge');
  badge.textContent = riskLevel;
  badge.className = `risk-badge ${riskClass}`;

  document.getElementById('domainDisplay').textContent = domain;
  document.getElementById('riskScore').textContent = `Risk Score: ${score}/100`;

  // Individual check cards
  const checkMap = [
    { card: 'checkPhishing', status: 'statusPhishing', result: results.phishing },
    { card: 'checkMalware', status: 'statusMalware', result: results.malware },
    { card: 'checkSuspTLD', status: 'statusSuspTLD', result: results.suspTLD },
    { card: 'checkBrandImperson', status: 'statusBrandImperson', result: results.brandImperson },
    { card: 'checkTyposquat', status: 'statusTyposquat', result: results.typosquat },
    { card: 'checkBogusDNS', status: 'statusBogusDNS', result: results.dnsStructure },
  ];

  checkMap.forEach(({ card, status, result }) => {
    const cardEl = document.getElementById(card);
    const statusEl = document.getElementById(status);

    if (isSafe) {
      cardEl.className = 'check-card pass';
      statusEl.textContent = '✅ PASS';
      statusEl.className = 'check-status status-pass';
    } else if (result.flagged === true) {
      cardEl.className = 'check-card fail';
      statusEl.textContent = '🚨 FLAGGED';
      statusEl.className = 'check-status status-fail';
    } else if (result.flagged === 'warn') {
      cardEl.className = 'check-card warn';
      statusEl.textContent = '⚠️ WARN';
      statusEl.className = 'check-status status-warn';
    } else {
      cardEl.className = 'check-card pass';
      statusEl.textContent = '✅ PASS';
      statusEl.className = 'check-status status-pass';
    }
  });

  // Summary box
  const summaryEl = document.getElementById('summaryBox');
  if (isSafe || score === 0) {
    summaryEl.className = 'summary-box safe';
    summaryEl.innerHTML = `<strong>✅ This domain appears safe.</strong> <em>${domain}</em> passed all DNS abuse checks and is not associated with any known phishing, malware, or domain abuse activity.`;
  } else if (score >= 40) {
    summaryEl.className = 'summary-box danger';
    const flaggedChecks = Object.values(results).filter(r => r.flagged === true).map(r => r.reason);
    summaryEl.innerHTML = `<strong>🚨 WARNING — This domain shows HIGH RISK indicators.</strong> We strongly advise against visiting or entering any personal information on this domain. Issues found: <br><br>• ${flaggedChecks.join('<br>• ')}`;
  } else if (score >= 20) {
    summaryEl.className = 'summary-box warning';
    summaryEl.innerHTML = `<strong>⚠️ This domain shows some suspicious patterns.</strong> Exercise caution. Double-check the URL carefully before entering any login or payment information.`;
  } else {
    summaryEl.className = 'summary-box safe';
    summaryEl.innerHTML = `<strong>✅ This domain appears likely safe</strong> with no major red flags detected. Always verify URLs carefully before sharing sensitive information online.`;
  }

  // ICANN note
  document.getElementById('icannNote').innerHTML = `
    🌐 <strong>About this check:</strong> This tool uses heuristic analysis aligned with ICANN's DNS Abuse definitions — 
    including phishing, malware, spam, and domain impersonation. For definitive verification, report suspicious domains 
    to <a href="https://www.icann.org/compliance/complaint" target="_blank" style="color:var(--accent)">ICANN Compliance</a> 
    or <a href="https://www.phishtank.com" target="_blank" style="color:var(--accent)">PhishTank</a>.
  `;

  // Report button (only show for risky domains)
  const reportBox = document.getElementById('reportBtnBox');
  if (score >= 20) {
    reportBox.innerHTML = `<button onclick="prefillReport('${domain}')">🚨 Report this Domain to Authorities</button>`;
  } else {
    reportBox.innerHTML = '';
  }
}

function prefillReport(domain) {
  document.getElementById('reportDomain').value = domain;
  document.querySelector('#report').scrollIntoView({ behavior: 'smooth' });
}

function submitReport() {
  const domain = document.getElementById('reportDomain').value.trim();
  const abuseType = document.getElementById('abuseType').value;

  if (!domain) { alert('Please enter a domain to report.'); return; }
  if (!abuseType) { alert('Please select the type of abuse.'); return; }

  // Simulate report submission
  setTimeout(() => {
    document.getElementById('reportSuccess').classList.remove('hidden');
    // Reset form
    document.getElementById('reportDomain').value = '';
    document.getElementById('abuseType').value = '';
    document.getElementById('reportDesc').value = '';
    document.getElementById('reportEmail').value = '';

    // Log to console (in production, this would POST to a backend)
    console.log('DNS Abuse Report Submitted:', {
      domain,
      abuseType,
      description: document.getElementById('reportDesc').value,
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent
    });

    setTimeout(() => document.getElementById('reportSuccess').classList.add('hidden'), 6000);
  }, 500);
}

// Smooth scroll for nav links
document.querySelectorAll('a[href^="#"]').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    const target = document.querySelector(a.getAttribute('href'));
    if (target) target.scrollIntoView({ behavior: 'smooth' });
  });
});

// Allow Enter key in domain input
document.addEventListener('DOMContentLoaded', () => {
  const input = document.getElementById('domainInput');
  if (input) {
    input.addEventListener('keydown', e => {
      if (e.key === 'Enter') checkDomain();
    });
  }
});