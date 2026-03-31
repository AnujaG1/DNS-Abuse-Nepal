// ═══════════════════════════════════════════════════
//  SECTION 1 — KNOWLEDGE BASES
// ═══════════════════════════════════════════════════

const TLD_ABUSE_SCORES = {
  '.tk': 0.97, '.ml': 0.95, '.ga': 0.93, '.cf': 0.91, '.gq': 0.89,
  '.xyz': 0.72, '.pw': 0.71, '.top': 0.65, '.click': 0.63,
  '.online': 0.58, '.site': 0.56, '.icu': 0.55, '.cam': 0.60,
  '.sbs': 0.52, '.cyou': 0.51, '.info': 0.35, '.biz': 0.30,
  '.cc': 0.45, '.ws': 0.40,
  '.co': 0.12, '.io': 0.08, '.app': 0.05, '.dev': 0.04,
  '.com': 0.05, '.org': 0.04, '.net': 0.05, '.edu': 0.01, '.gov': 0.01,
  '.gov.np': 0.00, '.edu.np': 0.01, '.com.np': 0.03,
  '.org.np': 0.02, '.net.np': 0.02, '.np': 0.03,
};

const NEPAL_BRANDS = [
  'ncell','ntc','nepalitelecom','esewa','khalti','fonepay','connectips',
  'nabilbank','nabil','nicasia','nicasiabank','primebank','everestbank',
  'himalayan','hbl','citizenbank','siddhartha','machapuchre','sunrise',
  'nea','nepalelectricity','wlink','worldlink','subisu','vianet','ntcnet',
  'nagarikta','passport','immigration','election','mofa','moha','mof',
  'nepalpolice','army','nasc','tribhuvan','ku','pokhara','kathmandu',
  'nepal','gov','nrb'
];

const WHITELIST = new Set([
  'google.com','facebook.com','youtube.com','github.com','wikipedia.org',
  'nepal.gov.np','mof.gov.np','moha.gov.np','parliament.gov.np',
  'nta.gov.np','election.gov.np','passport.gov.np','immigration.gov.np',
  'nabilbank.com','nicasiabank.com','esewa.com.np','khalti.com',
  'ncell.axiata.com','ntc.net.np','worldlink.com.np','subisu.net.np',
  'anthropic.com','icann.org','cloudflare.com','amazon.com','microsoft.com',
  'apple.com','twitter.com','instagram.com','linkedin.com','stackoverflow.com',
  'nrb.org.np','himalayanbank.com','primebank.com.np','siddhartha.com.np',
]);

const PHISHING_KEYWORDS = {
  'login': 0.25, 'signin': 0.25, 'secure': 0.20, 'verify': 0.22,
  'update': 0.15, 'account': 0.18, 'banking': 0.22, 'payment': 0.20,
  'wallet': 0.18, 'password': 0.28, 'credential': 0.28, 'confirm': 0.16,
  'validation': 0.20, 'alert': 0.14, 'suspended': 0.22, 'locked': 0.22,
  'recover': 0.18, 'reset': 0.16, 'authenticate': 0.24, 'authorize': 0.22,
  'free': 0.12, 'offer': 0.14, 'prize': 0.18, 'win': 0.14, 'claim': 0.16,
  'urgent': 0.20, 'limited': 0.12, 'bonus': 0.14, 'cashback': 0.16,
  'recharge': 0.12, 'topup': 0.12, 'apply': 0.10, 'renew': 0.14,
};

const FEATURE_WEIGHTS = {
  domainLength: 0.03,
  sldLength: 0.035,
  shannonEntropy: 8,
  digitRatio: 18,
  hyphenCount: 6.5,
  dotCount: 3,
  vowelRatio: 5,
  consonantCluster: 4.5,
  uniqueCharRatio: 4,
  numericSequence: 7,
  tldAbuseScore: 22,
  phishingKeywordScore: 20,
  brandMatchScore: 25,
  typosquatScore: 20,
  subdomainDepth: 2.5,
  hasIPAddress: 30,
  hexCharRatio: 12,
  ngramSuspicion: 6,
  atSymbol: 35,
  portNumber: 20,
};

//  ═══════════════════════════════════════════════════
 //  SECTION 2 — HELPERS (FIXED)
 // ═══════════════════════════════════════════════════

function normalizeDomain(raw) {
  try {
    const url = new URL(raw.includes('://') ? raw : `http://${raw}`);
    return {
      hostname: url.hostname.toLowerCase(),
      hasPort: url.port ? 1 : 0,
    };
  } catch {
    return {
      hostname: raw.toLowerCase(),
      hasPort: /:\d+/.test(raw) ? 1 : 0,
    };
  }
}

function isWhitelisted(domain) {
  return [...WHITELIST].some(w => domain === w || domain.endsWith(`.${w}`));
}

function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m+1 }, () => Array(n+1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

function getTLDAbuseScore(domain) {
  const d = domain.toLowerCase();
  for (const tld of Object.keys(TLD_ABUSE_SCORES).sort((a,b)=>b.length-a.length)) {
    if (d.endsWith(tld)) return { score: TLD_ABUSE_SCORES[tld], tld };
  }
  return { score: 0.25, tld: 'unknown' };
}

function getSLD(domain) {
  const parts = domain.split('.');
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
}

// ═══════════════════════════════════════════════════
//  SECTION 3 — FEATURE EXTRACTION (FIXED)
// ═══════════════════════════════════════════════════

function extractFeatures(rawDomain) {
  const { hostname, hasPort } = normalizeDomain(rawDomain);
  const domain = hostname;

  const sld = getSLD(domain);
  const { score: tldScore, tld } = getTLDAbuseScore(domain);
  const whitelist = isWhitelisted(domain);

  const digits = (domain.match(/\d/g) || []).length;
  const letters = (domain.match(/[a-z]/g) || []).length;
  const vowels = (domain.match(/[aeiou]/g) || []).length;

  const vowelRatio = letters ? Math.abs((vowels / letters) - 0.38) : 0;

  const hyphens = (domain.match(/-/g) || []).length;
  const dots = (domain.match(/\./g) || []).length;

  const hasIPAddress = /\b\d{1,3}(\.\d{1,3}){3}\b/.test(domain) ? 1 : 0;

  // Brand detection FIXED
  let brandMatchScore = 0;
  for (const brand of NEPAL_BRANDS) {
    const regex = new RegExp(`(^|\\.|-)${brand}($|\\.|-)`);
    if (regex.test(domain) && !whitelist) {
      brandMatchScore = Math.max(brandMatchScore, brand.length / sld.length);
    }
  }

  // Typosquat FIXED
  const POPULAR = ['google','facebook','esewa','khalti','ncell'];
  let minDist = Infinity;
  for (const p of POPULAR) {
    minDist = Math.min(minDist, levenshtein(sld, p));
  }

  let typosquatScore = 0;
  if (minDist === 1) typosquatScore = 0.95;
  else if (minDist === 2) typosquatScore = 0.75;
  else if (minDist === 3) typosquatScore = 0.35;

  return {
    _isWhitelisted: whitelist,
    domainLength: domain.length,
    sldLength: sld.length,
    shannonEntropy: shannonEntropy(domain),
    digitRatio: digits / Math.max(1, domain.length),
    hyphenCount: hyphens,
    dotCount: dots,
    vowelRatio,
    consonantCluster: 0,
    uniqueCharRatio: new Set(domain).size / domain.length,
    numericSequence: 0,
    tldAbuseScore: tldScore,
    phishingKeywordScore: 0,
    brandMatchScore,
    typosquatScore,
    subdomainDepth: Math.max(0, domain.split('.').length - 2),
    hasIPAddress,
    hexCharRatio: 0,
    ngramSuspicion: 0,
    atSymbol: domain.includes('@') ? 1 : 0,
    portNumber: hasPort,
  };
}

// ═══════════════════════════════════════════════════
//  SECTION 4 — SCORING (FIXED)
// ═══════════════════════════════════════════════════

function computeMLScore(features) {
  if (features._isWhitelisted) return { score: 0 };

  let raw = 0;
  let max = 0;

  for (const key in FEATURE_WEIGHTS) {
    const w = FEATURE_WEIGHTS[key];
    const v = features[key] || 0;
    raw += v * w;
    max += w;
  }

  return {
    score: Math.min(100, Math.round((raw / max) * 100))
  };
}

// ═══════════════════════════════════════════════════
//  SECTION 5 — MAIN PIPELINE
// ═══════════════════════════════════════════════════

function analyzeDomain(domain) {
  const features = extractFeatures(domain);
  const { score } = computeMLScore(features);

  let riskLevel = 'safe';
  if (score > 50) riskLevel = 'danger';
  else if (score > 20) riskLevel = 'warning';

  return { features, score, riskLevel };
}

// ═══════════════════════════════════════════════════
//  TEST
// ═══════════════════════════════════════════════════

console.log(analyzeDomain("http://secure-esewa-login.tk"));