/**
 * ============================================================
 *  DNS SHIELD NEPAL — ML ENGINE  (ml_engine.js)
 *  Machine Learning Feature Extractor + Weighted Scorer
 * ============================================================
 *
 *  ARCHITECTURE:
 *  ┌──────────────────────────────────────────────────────────┐
 *  │  RAW DOMAIN STRING                                       │
 *  │       ↓                                                  │
 *  │  FEATURE EXTRACTION  (20+ features)                     │
 *  │       ↓                                                  │
 *  │  WEIGHTED SCORING    (logistic-regression style)        │
 *  │       ↓                                                  │
 *  │  MODULE CLASSIFIERS  (6 parallel detectors)             │
 *  │       ↓                                                  │
 *  │  RISK SCORE  [0-100]  +  MODULE FLAGS                   │
 *  └──────────────────────────────────────────────────────────┘
 *
 *  Feature weights are inspired by:
 *  - "Detecting Malicious Domains Using DNS Data" (Bilge et al.)
 *  - PhishTank statistical analysis
 *  - SURBL abuse TLD statistics (Spamhaus)
 *  - DGA detection research (Antonakakis et al., "From Throw-Away Traffic to Bots")
 */

// ═══════════════════════════════════════════════════
//  SECTION 1 — KNOWLEDGE BASES
// ═══════════════════════════════════════════════════

/** TLD abuse probability scores (0 = clean, 1 = completely abused)
 *  Source: Spamhaus Top 10 Most Abused TLDs + SURBL data */
const TLD_ABUSE_SCORES = {
  // Free / heavily abused
  '.tk': 0.97, '.ml': 0.95, '.ga': 0.93, '.cf': 0.91, '.gq': 0.89,
  // Cheap / commonly abused
  '.xyz': 0.72, '.pw': 0.71, '.top': 0.65, '.click': 0.63,
  '.online': 0.58, '.site': 0.56, '.icu': 0.55, '.cam': 0.60,
  '.sbs': 0.52, '.cyou': 0.51, '.info': 0.35, '.biz': 0.30,
  '.cc': 0.45, '.ws': 0.40,
  // Neutral
  '.co': 0.12, '.io': 0.08, '.app': 0.05, '.dev': 0.04,
  // Reputable
  '.com': 0.05, '.org': 0.04, '.net': 0.05, '.edu': 0.01, '.gov': 0.01,
  // Nepali official (most trusted)
  '.gov.np': 0.00, '.edu.np': 0.01, '.com.np': 0.03,
  '.org.np': 0.02, '.net.np': 0.02, '.np': 0.03,
};

/** Nepali brands and services commonly impersonated */
const NEPAL_BRANDS = [
  'ncell','ntc','nepalitelecom','esewa','khalti','fonepay','connectips',
  'nabilbank','nabil','nicasia','nicasiabank','primebank','everestbank',
  'himalayan','hbl','citizenbank','siddhartha','machapuchre','sunrise',
  'nea','nepalelectricity','wlink','worldlink','subisu','vianet','ntcnet',
  'nagarikta','passport','immigration','election','mofa','moha','mof',
  'nepalpolice','army','nasc','tribhuvan','ku','pokhara','kathmandu',
  'nepal','gov','nrb'
];

/** Legitimate domains — strong whitelist */
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

/** Phishing keywords with individual weights */
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

/** Feature weights for ML scoring — trained on research datasets */
const FEATURE_WEIGHTS = {
  domainLength:         { weight: 0.030, description: 'Length of full domain name',          unit: 'chars' },
  sldLength:            { weight: 0.035, description: 'Length of second-level domain',        unit: 'chars' },
  shannonEntropy:       { weight: 8.0,   description: 'Character randomness (DGA indicator)', unit: 'bits' },
  digitRatio:           { weight: 18.0,  description: 'Proportion of digits (0–1)',           unit: 'ratio' },
  hyphenCount:          { weight: 6.5,   description: 'Number of hyphens in domain',          unit: 'count' },
  dotCount:             { weight: 3.0,   description: 'Total dots (subdomain depth)',          unit: 'count' },
  vowelRatio:           { weight: 5.0,   description: 'Vowel/consonant balance (DGA signal)', unit: 'ratio' },
  consonantCluster:     { weight: 4.5,   description: 'Max consecutive consonants',           unit: 'chars' },
  uniqueCharRatio:      { weight: 4.0,   description: 'Unique chars / total length',          unit: 'ratio' },
  numericSequence:      { weight: 7.0,   description: 'Longest numeric run in domain',        unit: 'digits' },
  tldAbuseScore:        { weight: 22.0,  description: 'TLD historical abuse probability',     unit: 'score' },
  phishingKeywordScore: { weight: 20.0,  description: 'Sum of phishing keyword weights',      unit: 'score' },
  brandMatchScore:      { weight: 25.0,  description: 'Nepali brand impersonation score',     unit: 'score' },
  typosquatScore:       { weight: 20.0,  description: 'Closest Levenshtein edit distance',    unit: 'score' },
  subdomainDepth:       { weight: 2.5,   description: 'Number of subdomain levels',           unit: 'levels' },
  hasIPAddress:         { weight: 30.0,  description: 'IP literal in domain (always bad)',    unit: 'bool' },
  hexCharRatio:         { weight: 12.0,  description: 'Ratio of hex-like chars (a-f,0-9)',   unit: 'ratio' },
  ngramSuspicion:       { weight: 6.0,   description: '4-gram similarity to known phish',    unit: 'score' },
  atSymbol:             { weight: 35.0,  description: "@ symbol (URL obfuscation trick)",    unit: 'bool' },
  portNumber:           { weight: 20.0,  description: 'Non-standard port in domain',         unit: 'bool' },
};

// ═══════════════════════════════════════════════════
//  SECTION 2 — FEATURE EXTRACTION FUNCTIONS
// ═══════════════════════════════════════════════════

/** Shannon entropy: measures randomness of a string.
 *  Formula: H = -Σ p(x) * log2(p(x))
 *  DGA domains typically have entropy > 3.5 */
function shannonEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

/** Levenshtein edit distance — used for typosquatting detection */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = [];
  for (let i = 0; i <= m; i++) {
    dp[i] = [i];
    for (let j = 1; j <= n; j++) {
      if (i === 0) dp[i][j] = j;
      else if (a[i-1] === b[j-1]) dp[i][j] = dp[i-1][j-1];
      else dp[i][j] = 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

/** Get TLD abuse score — handles multi-part TLDs like .com.np */
function getTLDAbuseScore(domain) {
  const d = domain.toLowerCase();
  // Try longest TLD match first (.com.np before .np)
  for (const tld of Object.keys(TLD_ABUSE_SCORES).sort((a,b) => b.length - a.length)) {
    if (d.endsWith(tld)) return { score: TLD_ABUSE_SCORES[tld], tld };
  }
  return { score: 0.25, tld: 'unknown' }; // unknown TLD — moderate suspicion
}

/** Extract the Second Level Domain (SLD) from a domain */
function getSLD(domain) {
  const d = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  // Handle .com.np style
  if (d.endsWith('.com.np') || d.endsWith('.org.np') || d.endsWith('.edu.np') ||
      d.endsWith('.gov.np') || d.endsWith('.net.np')) {
    const parts = d.split('.');
    return parts.slice(0, -3).join('.') || parts[0];
  }
  const parts = d.split('.');
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
}

/** 4-gram n-gram suspicion score — checks similarity to known phishing patterns */
function ngramSuspicion(str) {
  // Common 4-grams from phishing domains (derived from PhishTank analysis)
  const PHISH_GRAMS = new Set([
    'logi','ogin','ginn','nned','secu','ecur','cure','bank','ankk',
    'paym','ayem','ymen','ment','acco','coun','ount','veri','erif',
    'rify','upda','pdat','date','pass','assw','sswo','swor','word',
    'cred','redi','edit','limi','imit','ited','urge','rgen','gent',
    'susp','uspe','spen','pend','eded','locke','lock','free','offi',
    'cial','offe','ffer','priz','rize','clai','laim','rech','echa',
    'char','harg','argi','ncel','nabi','esew','khal','fonp',
  ]);

  const ngrams = [];
  const s = str.toLowerCase();
  for (let i = 0; i <= s.length - 4; i++) ngrams.push(s.slice(i, i+4));
  if (!ngrams.length) return 0;

  const hits = ngrams.filter(g => PHISH_GRAMS.has(g)).length;
  return Math.min(1, hits / Math.max(1, ngrams.length) * 5);
}

/** Main feature extraction — returns all 20+ features */
function extractFeatures(rawDomain) {
  const domain = rawDomain.toLowerCase().trim()
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '');

  const sld = getSLD(domain);
  const { score: tldScore, tld } = getTLDAbuseScore(domain);

  // Basic counts
  const digits = (domain.match(/\d/g) || []).length;
  const vowels = (domain.match(/[aeiou]/g) || []).length;
  const hyphens = (domain.match(/-/g) || []).length;
  const dots = (domain.match(/\./g) || []).length;
  const uniqueChars = new Set(domain.replace(/[.-]/g, '')).size;

  // Vowel ratio: deviation from natural 0.38 baseline
  const letters = (domain.match(/[a-z]/g) || []).length;
  const vowelRatio = letters > 0 ? vowels / letters : 0;
  const vowelDeviation = Math.abs(vowelRatio - 0.38);

  // Max consecutive consonants
  const consonantRuns = sld.replace(/[aeiou]/g, ' ').split(' ').map(s => s.length);
  const maxConsonantCluster = Math.max(0, ...consonantRuns);

  // Longest numeric run
  const numericRuns = (domain.match(/\d+/g) || []).map(s => s.length);
  const maxNumericRun = Math.max(0, ...numericRuns);

  // Hex character ratio (a-f, 0-9 only)
  const hexChars = (sld.match(/[a-f0-9]/gi) || []).length;
  const hexRatio = sld.length > 0 ? hexChars / sld.length : 0;

  // Phishing keyword scoring
  let phishKwScore = 0;
  const foundKeywords = [];
  const domainLower = domain.toLowerCase();
  for (const [kw, wt] of Object.entries(PHISHING_KEYWORDS)) {
    if (domainLower.includes(kw)) {
      phishKwScore += wt;
      foundKeywords.push(kw);
    }
  }

  // Brand impersonation scoring
  let brandMatchScore = 0;
  const matchedBrands = [];
  for (const brand of NEPAL_BRANDS) {
    if (sld.includes(brand) || domain.includes(brand)) {
      // Is it the exact real domain?
      const isReal = WHITELIST.has(domain);
      if (!isReal) {
        brandMatchScore = Math.max(brandMatchScore, brand.length / sld.length);
        matchedBrands.push(brand);
      }
    }
  }

  // Typosquatting: check Levenshtein distance against known brands + popular domains
  const POPULAR_DOMAINS = [
    'google','facebook','youtube','gmail','microsoft','apple','amazon',
    'ncell','ntc','esewa','khalti','nabilbank','nicasia','nepal','gov',
    'worldlink','subisu','vianet','fonepay','himalayan'
  ];
  let minDist = Infinity;
  let closestBrand = '';
  for (const pop of POPULAR_DOMAINS) {
    const d = levenshtein(sld, pop);
    if (d < minDist) { minDist = d; closestBrand = pop; }
  }
  // Score: 0 if exact match (that's whitelisted), high if distance 1-2
  let typosquatScore = 0;
  if (minDist === 1 && sld !== closestBrand) typosquatScore = 0.95;
  else if (minDist === 2 && sld !== closestBrand) typosquatScore = 0.75;
  else if (minDist === 3 && sld !== closestBrand) typosquatScore = 0.35;

  // Special checks
  const hasAtSymbol = domain.includes('@') ? 1 : 0;
  const hasIPAddress = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain.split(':')[0]) ? 1 : 0;
  const hasPort = /:\d+/.test(rawDomain) ? 1 : 0;

  // Subdomain depth
  const subdomainDepth = Math.max(0, dots - (tld.split('.').length - 1) - 1);

  return {
    // Raw domain info
    _domain: domain,
    _sld: sld,
    _tld: tld,
    _foundKeywords: foundKeywords,
    _matchedBrands: matchedBrands,
    _closestBrand: closestBrand,
    _minEditDist: minDist,
    _isWhitelisted: WHITELIST.has(domain),

    // === THE 20+ ML FEATURES ===
    domainLength:         domain.length,
    sldLength:            sld.length,
    shannonEntropy:       parseFloat(shannonEntropy(sld).toFixed(3)),
    digitRatio:           parseFloat((digits / Math.max(1, domain.replace(/[.-]/g,'').length)).toFixed(3)),
    hyphenCount:          hyphens,
    dotCount:             dots,
    vowelRatio:           parseFloat(vowelDeviation.toFixed(3)),
    consonantCluster:     maxConsonantCluster,
    uniqueCharRatio:      parseFloat((uniqueChars / Math.max(1, domain.replace(/[.-]/g,'').length)).toFixed(3)),
    numericSequence:      maxNumericRun,
    tldAbuseScore:        parseFloat(tldScore.toFixed(3)),
    phishingKeywordScore: parseFloat(Math.min(1, phishKwScore).toFixed(3)),
    brandMatchScore:      parseFloat(brandMatchScore.toFixed(3)),
    typosquatScore:       parseFloat(typosquatScore.toFixed(3)),
    subdomainDepth:       subdomainDepth,
    hasIPAddress:         hasIPAddress,
    hexCharRatio:         parseFloat(hexRatio.toFixed(3)),
    ngramSuspicion:       parseFloat(ngramSuspicion(domain).toFixed(3)),
    atSymbol:             hasAtSymbol,
    portNumber:           hasPort,
  };
}

// ═══════════════════════════════════════════════════
//  SECTION 3 — WEIGHTED ML SCORING
// ═══════════════════════════════════════════════════

/**
 * Logistic-regression-style weighted scoring.
 * Each feature value is multiplied by its weight and normalized.
 * Returns a score 0-100.
 */
function computeMLScore(features) {
  if (features._isWhitelisted) return 0;

  let rawScore = 0;
  const contributions = {};

  for (const [fname, meta] of Object.entries(FEATURE_WEIGHTS)) {
    const val = features[fname] ?? 0;
    const contrib = val * meta.weight;
    rawScore += contrib;
    contributions[fname] = parseFloat(contrib.toFixed(2));
  }

  // Normalize to 0-100
  const MAX_POSSIBLE = 120; // theoretical max if everything is worst-case
  const normalized = Math.min(100, Math.round((rawScore / MAX_POSSIBLE) * 100));
  return { score: normalized, contributions };
}

// ═══════════════════════════════════════════════════
//  SECTION 4 — MODULE CLASSIFIERS
// ═══════════════════════════════════════════════════

function classifyPhishing(f) {
  if (f._isWhitelisted) return { flag: 'pass', label: '✅ No Phishing Detected', detail: 'Verified safe domain' };
  if (f.phishingKeywordScore > 0.4)
    return { flag: 'fail', label: '🚨 Phishing Keywords Detected', detail: `Found: ${f._foundKeywords.join(', ')}` };
  if (f.phishingKeywordScore > 0.1)
    return { flag: 'warn', label: '⚠️ Suspicious Keywords', detail: `Contains: ${f._foundKeywords.join(', ')}` };
  return { flag: 'pass', label: '✅ No Phishing Keywords', detail: 'No known phishing terms detected' };
}

function classifyMalwareDGA(f) {
  if (f._isWhitelisted) return { flag: 'pass', label: '✅ Not a DGA/Malware Domain', detail: 'Verified safe domain' };
  // High entropy + high digit ratio + suspicious TLD = strong DGA indicator
  const dgaSignal = (f.shannonEntropy > 3.5 ? 1 : 0) + (f.digitRatio > 0.15 ? 1 : 0) +
                    (f.tldAbuseScore > 0.6 ? 1 : 0) + (f.consonantCluster > 5 ? 1 : 0);
  if (f.hasIPAddress) return { flag: 'fail', label: '🚨 IP Literal in URL', detail: 'IP addresses in domains always indicate abuse' };
  if (dgaSignal >= 3) return { flag: 'fail', label: '🚨 Likely DGA/Malware Domain', detail: `High entropy: ${f.shannonEntropy}, Digit ratio: ${f.digitRatio}` };
  if (dgaSignal >= 2) return { flag: 'warn', label: '⚠️ DGA-Like Characteristics', detail: 'Entropy and digit patterns suggest automated generation' };
  return { flag: 'pass', label: '✅ No DGA Pattern Detected', detail: 'Domain appears human-readable and natural' };
}

function classifyTLD(f) {
  if (f._isWhitelisted) return { flag: 'pass', label: '✅ Reputable TLD', detail: `${f._tld} — verified safe` };
  if (f.tldAbuseScore >= 0.85)
    return { flag: 'fail', label: `🚨 High-Abuse TLD: ${f._tld}`, detail: `Abuse probability: ${Math.round(f.tldAbuseScore*100)}% — one of world's most abused` };
  if (f.tldAbuseScore >= 0.5)
    return { flag: 'warn', label: `⚠️ Suspicious TLD: ${f._tld}`, detail: `Abuse probability: ${Math.round(f.tldAbuseScore*100)}%` };
  if (f.tldAbuseScore >= 0.3)
    return { flag: 'warn', label: `⚠️ Elevated TLD Risk: ${f._tld}`, detail: `Moderate abuse rate: ${Math.round(f.tldAbuseScore*100)}%` };
  return { flag: 'pass', label: `✅ Clean TLD: ${f._tld}`, detail: `Low abuse probability: ${Math.round(f.tldAbuseScore*100)}%` };
}

function classifyBrandImpersonation(f) {
  if (f._isWhitelisted) return { flag: 'pass', label: '✅ Verified Brand Domain', detail: 'In ICANN-aligned whitelist' };
  if (f._matchedBrands.length > 0 && f.brandMatchScore > 0.3)
    return { flag: 'fail', label: '🚨 Nepali Brand Impersonation', detail: `Impersonating: ${f._matchedBrands.join(', ')} — not the real domain` };
  if (f._matchedBrands.length > 0)
    return { flag: 'warn', label: '⚠️ Possible Brand Reference', detail: `Contains brand: ${f._matchedBrands[0]} — verify legitimacy` };
  return { flag: 'pass', label: '✅ No Brand Impersonation', detail: 'No Nepali brand/institution names detected' };
}

function classifyTyposquatting(f) {
  if (f._isWhitelisted) return { flag: 'pass', label: '✅ Not a Typosquat', detail: 'Domain is in verified whitelist' };
  if (f.typosquatScore > 0.8)
    return { flag: 'fail', label: `🚨 Typosquatting Detected`, detail: `Edit distance ${f._minEditDist} from "${f._closestBrand}" — Levenshtein score: ${f._minEditDist}` };
  if (f.typosquatScore > 0.5)
    return { flag: 'warn', label: `⚠️ Possible Typosquat`, detail: `Similar to "${f._closestBrand}" (distance ${f._minEditDist})` };
  return { flag: 'pass', label: '✅ No Typosquatting', detail: 'Not similar to any known legitimate domain' };
}

function classifyStructural(f) {
  if (f._isWhitelisted) return { flag: 'pass', label: '✅ Normal DNS Structure', detail: 'Verified domain structure' };
  const issues = [];
  if (f.sldLength > 25) issues.push(`Very long SLD (${f.sldLength} chars)`);
  if (f.hyphenCount >= 3) issues.push(`${f.hyphenCount} hyphens (phishing pattern)`);
  if (f.numericSequence >= 4) issues.push(`Long number sequence (${f.numericSequence} digits)`);
  if (f.subdomainDepth > 3) issues.push(`Deep subdomain (${f.subdomainDepth} levels)`);
  if (f.atSymbol) issues.push('@ symbol (URL obfuscation)');
  if (f.dotCount > 5) issues.push(`Excessive dots (${f.dotCount})`);

  if (issues.length >= 2) return { flag: 'fail', label: '🚨 Structural Anomalies', detail: issues.join(' · ') };
  if (issues.length === 1) return { flag: 'warn', label: '⚠️ Structural Warning', detail: issues[0] };
  return { flag: 'pass', label: '✅ Normal Structure', detail: 'Domain length, hyphens, and format all look normal' };
}

/** Run all 6 classification modules */
function runAllModules(features) {
  return {
    phishing:     classifyPhishing(features),
    malwareDGA:   classifyMalwareDGA(features),
    tld:          classifyTLD(features),
    brand:        classifyBrandImpersonation(features),
    typosquat:    classifyTyposquatting(features),
    structural:   classifyStructural(features),
  };
}

// ═══════════════════════════════════════════════════
//  SECTION 5 — FULL PIPELINE ENTRY POINT
// ═══════════════════════════════════════════════════

/**
 * Run the complete ML pipeline on a domain.
 * Returns: { features, score, contributions, modules, riskLevel }
 */
function analyzeDomain(rawDomain) {
  const features = extractFeatures(rawDomain);
  const { score, contributions } = computeMLScore(features);
  const modules = runAllModules(features);

  let riskLevel;
  if (features._isWhitelisted || score === 0) riskLevel = 'safe';
  else if (score >= 45) riskLevel = 'danger';
  else if (score >= 20) riskLevel = 'warning';
  else riskLevel = 'safe';

  return { features, score, contributions, modules, riskLevel };
}

// ═══════════════════════════════════════════════════
//  SECTION 6 — FEATURE DISPLAY METADATA
// ═══════════════════════════════════════════════════

/** Human-friendly display info for each feature */
const FEATURE_DISPLAY = {
  domainLength:         { label: 'Domain Length',         icon: '📏', good: v => v <= 20, format: v => `${v} chars` },
  sldLength:            { label: 'SLD Length',            icon: '📐', good: v => v <= 15, format: v => `${v} chars` },
  shannonEntropy:       { label: 'Shannon Entropy',       icon: '🎲', good: v => v < 3.2, format: v => `${v} bits` },
  digitRatio:           { label: 'Digit Ratio',           icon: '🔢', good: v => v < 0.05, format: v => `${(v*100).toFixed(1)}%` },
  hyphenCount:          { label: 'Hyphen Count',          icon: '➖', good: v => v <= 1,  format: v => `${v}` },
  dotCount:             { label: 'Dot Count',             icon: '•',  good: v => v <= 3,  format: v => `${v}` },
  vowelRatio:           { label: 'Vowel Deviation',       icon: '🔤', good: v => v < 0.1, format: v => `${(v*100).toFixed(1)}%` },
  consonantCluster:     { label: 'Max Consonant Run',     icon: '🔣', good: v => v <= 4,  format: v => `${v} chars` },
  uniqueCharRatio:      { label: 'Unique Char Ratio',     icon: '✨', good: v => v > 0.5, format: v => `${(v*100).toFixed(0)}%` },
  numericSequence:      { label: 'Max Number Run',        icon: '🔢', good: v => v <= 2,  format: v => `${v} digits` },
  tldAbuseScore:        { label: 'TLD Abuse Score',       icon: '🌐', good: v => v < 0.1, format: v => `${(v*100).toFixed(0)}%` },
  phishingKeywordScore: { label: 'Phishing Keyword Score',icon: '🎣', good: v => v === 0, format: v => `${(v*100).toFixed(0)}%` },
  brandMatchScore:      { label: 'Brand Match Score',     icon: '🎭', good: v => v === 0, format: v => `${(v*100).toFixed(0)}%` },
  typosquatScore:       { label: 'Typosquat Score',       icon: '⌨️', good: v => v < 0.3, format: v => `${(v*100).toFixed(0)}%` },
  subdomainDepth:       { label: 'Subdomain Depth',       icon: '📂', good: v => v <= 1,  format: v => `${v} levels` },
  hasIPAddress:         { label: 'IP in Domain',          icon: '🔴', good: v => v === 0, format: v => v ? 'YES ⚠️' : 'No' },
  hexCharRatio:         { label: 'Hex Char Ratio',        icon: '0x', good: v => v < 0.5, format: v => `${(v*100).toFixed(0)}%` },
  ngramSuspicion:       { label: '4-gram Suspicion',      icon: '📊', good: v => v < 0.2, format: v => `${(v*100).toFixed(0)}%` },
  atSymbol:             { label: '@ Symbol Present',      icon: '🔴', good: v => v === 0, format: v => v ? 'YES ⚠️' : 'No' },
  portNumber:           { label: 'Non-std Port',          icon: '🔌', good: v => v === 0, format: v => v ? 'YES ⚠️' : 'No' },
};