"""
features.py
===========
Extracts 22 numerical features from a raw domain string.
These features are fed into the ML model for training and prediction.

Every feature here has a mathematical or empirical basis from
DNS abuse detection research.
"""

import math
import re
from urllib.parse import urlparse


# ── Knowledge bases ───────────────────────────────────────────────────────────

TLD_ABUSE_SCORES = {
    # Free TLDs — near 100% abuse (Spamhaus data)
    ".tk": 0.97, ".ml": 0.95, ".ga": 0.93, ".cf": 0.91, ".gq": 0.89,
    # Cheap TLDs — high abuse
    ".xyz": 0.72, ".pw": 0.71, ".top": 0.65, ".click": 0.63,
    ".online": 0.58, ".site": 0.56, ".icu": 0.55, ".cam": 0.60,
    ".sbs": 0.52, ".cyou": 0.51, ".info": 0.35, ".biz": 0.30,
    ".cc": 0.45, ".ws": 0.40,
    # Neutral
    ".co": 0.12, ".io": 0.08, ".app": 0.05, ".dev": 0.04,
    # Reputable
    ".com": 0.05, ".org": 0.04, ".net": 0.05,
    ".edu": 0.01, ".gov": 0.01,
    # Nepali official (most trusted)
    ".gov.np": 0.00, ".edu.np": 0.01,
    ".com.np": 0.03, ".org.np": 0.02, ".net.np": 0.02, ".np": 0.03,
}

PHISHING_KEYWORDS = {
    "login": 0.25, "signin": 0.25, "secure": 0.20, "verify": 0.22,
    "update": 0.15, "account": 0.18, "banking": 0.22, "payment": 0.20,
    "wallet": 0.18, "password": 0.28, "confirm": 0.16, "alert": 0.14,
    "suspended": 0.22, "locked": 0.22, "recover": 0.18, "free": 0.12,
    "offer": 0.14, "prize": 0.18, "win": 0.14, "claim": 0.16,
    "urgent": 0.20, "recharge": 0.12, "apply": 0.10, "renew": 0.14,
    "bonus": 0.14, "reset": 0.16, "credential": 0.28,
}

NEPAL_BRANDS = [
    "ncell", "ntc", "esewa", "khalti", "fonepay", "connectips",
    "nabilbank", "nabil", "nicasia", "primebank", "everestbank",
    "himalayan", "hbl", "citizenbank", "siddhartha", "machapuchre",
    "nea", "worldlink", "subisu", "vianet", "wlink",
    "nagarikta", "passport", "immigration", "election",
    "mofa", "moha", "mof", "nrb",
]

# 4-grams common in phishing domains (from PhishTank analysis)
PHISH_4GRAMS = {
    "logi", "ogin", "secu", "ecur", "bank", "paym", "acco",
    "coun", "veri", "erif", "upda", "pass", "cred", "free",
    "offi", "cial", "offe", "priz", "clai", "rech", "ncel",
    "nabi", "esew", "khal", "susp", "lock", "urge",
}

WHITELIST = {
    "google.com", "facebook.com", "youtube.com", "github.com",
    "wikipedia.org", "nepal.gov.np", "mof.gov.np", "moha.gov.np",
    "parliament.gov.np", "nta.gov.np", "election.gov.np",
    "passport.gov.np", "immigration.gov.np", "nabilbank.com",
    "nicasiabank.com", "esewa.com.np", "khalti.com",
    "ncell.axiata.com", "ntc.net.np", "worldlink.com.np",
    "subisu.net.np", "anthropic.com", "icann.org", "cloudflare.com",
    "amazon.com", "microsoft.com", "apple.com", "nrb.org.np",
    "himalayanbank.com", "primebank.com.np", "siddhartha.com.np",
}

POPULAR_FOR_TYPO = [
    "google", "facebook", "youtube", "gmail", "microsoft", "apple",
    "amazon", "ncell", "ntc", "esewa", "khalti", "nabilbank", "nicasia",
]


# ── Helper functions ──────────────────────────────────────────────────────────

def clean_domain(raw: str) -> str:
    """Strip protocol, path, port from raw input."""
    raw = raw.lower().strip()
    raw = re.sub(r'^https?://', '', raw)
    raw = re.sub(r'/.*$', '', raw)
    raw = re.sub(r':\d+$', '', raw)
    return raw


def get_tld(domain: str) -> tuple[str, float]:
    """Return (tld, abuse_score). Matches longest TLD first."""
    for tld in sorted(TLD_ABUSE_SCORES.keys(), key=len, reverse=True):
        if domain.endswith(tld):
            return tld, TLD_ABUSE_SCORES[tld]
    return "unknown", 0.25


def get_sld(domain: str) -> str:
    """Extract second-level domain."""
    # Handle 3-part TLDs like .com.np
    if re.search(r'\.(com|org|edu|gov|net)\.np$', domain):
        parts = domain.split('.')
        return '.'.join(parts[:-3]) if len(parts) > 3 else parts[0]
    parts = domain.split('.')
    return parts[-2] if len(parts) >= 2 else parts[0]


def shannon_entropy(s: str) -> float:
    """
    Shannon entropy measures randomness.
    Formula: H = -sum(p(x) * log2(p(x)))
    DGA domains typically have entropy > 3.5 bits.
    """
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def levenshtein(a: str, b: str) -> int:
    """
    Edit distance between two strings.
    Used to detect typosquatting: dist('g00gle', 'google') = 2
    """
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[j] = prev[j - 1]
            else:
                dp[j] = 1 + min(prev[j], dp[j - 1], prev[j - 1])
    return dp[n]


def ngram_score(domain: str, n: int = 4) -> float:
    """Fraction of n-grams that appear in known phishing vocabulary."""
    grams = [domain[i:i+n] for i in range(len(domain) - n + 1)]
    if not grams:
        return 0.0
    hits = sum(1 for g in grams if g in PHISH_4GRAMS)
    return min(1.0, hits / len(grams) * 5)


# ── Main feature extractor ────────────────────────────────────────────────────

FEATURE_NAMES = [
    "domain_length",        # 1
    "sld_length",           # 2
    "shannon_entropy",      # 3  — DGA signal
    "digit_ratio",          # 4  — DGA / typosquat signal
    "hyphen_count",         # 5  — phishing pattern
    "dot_count",            # 6  — subdomain abuse
    "vowel_deviation",      # 7  — DGA signal (natural lang = 38% vowels)
    "consonant_cluster",    # 8  — DGA signal
    "unique_char_ratio",    # 9
    "numeric_sequence",     # 10 — long digit runs
    "tld_abuse_score",      # 11 — Spamhaus TLD data
    "phish_keyword_score",  # 12 — PhishTank keyword analysis
    "brand_match_score",    # 13 — Nepali brand impersonation
    "typosquat_score",      # 14 — Levenshtein distance
    "subdomain_depth",      # 15
    "has_ip",               # 16 — IP literal in domain
    "hex_char_ratio",       # 17 — hex-like strings
    "ngram_score",          # 18 — 4-gram phishing vocabulary
    "has_at_symbol",        # 19 — URL obfuscation
    "has_port",             # 20 — non-standard port
    "special_char_count",   # 21
    "is_whitelisted",       # 22
]


def extract_features(raw: str) -> dict:
    """
    Extract all 22 features from a domain string.
    Returns a dict {feature_name: value}.
    """
    domain = clean_domain(raw)
    sld = get_sld(domain)
    tld, tld_score = get_tld(domain)

    # Character-level stats
    clean = re.sub(r'[.\-]', '', domain)
    digits = sum(c.isdigit() for c in domain)
    letters_in_sld = sum(c.isalpha() for c in sld)
    vowels_in_sld = sum(c in 'aeiou' for c in sld)
    hyphens = domain.count('-')
    dots = domain.count('.')
    unique_chars = len(set(clean))

    # Vowel deviation from natural language baseline (38%)
    vow_ratio = vowels_in_sld / max(1, letters_in_sld)
    vow_deviation = abs(vow_ratio - 0.38)

    # Consonant cluster: longest consecutive consonant run
    consonant_runs = re.split(r'[aeiou\d\W]', sld)
    max_consonant = max((len(r) for r in consonant_runs), default=0)

    # Longest digit sequence
    digit_runs = re.findall(r'\d+', domain)
    max_numeric = max((len(r) for r in digit_runs), default=0)

    # Hex character ratio
    hex_chars = sum(1 for c in sld if c in 'abcdef0123456789')
    hex_ratio = hex_chars / max(1, len(sld))

    # Phishing keyword score
    phish_score = 0.0
    found_kw = []
    for kw, weight in PHISHING_KEYWORDS.items():
        if kw in domain:
            phish_score += weight
            found_kw.append(kw)
    phish_score = min(1.0, phish_score)

    # Brand impersonation score
    brand_score = 0.0
    found_brands = []
    if domain not in WHITELIST:
        for brand in NEPAL_BRANDS:
            if brand in sld or brand in domain:
                score = len(brand) / max(1, len(sld))
                brand_score = max(brand_score, score)
                found_brands.append(brand)
    brand_score = min(1.0, brand_score)

    # Typosquatting via Levenshtein distance
    min_dist = 999
    closest = ""
    for pop in POPULAR_FOR_TYPO:
        d = levenshtein(sld, pop)
        if d < min_dist:
            min_dist = d
            closest = pop
    typo_score = 0.0
    if min_dist == 1 and sld != closest:
        typo_score = 0.95
    elif min_dist == 2 and sld != closest and len(sld) > 3:
        typo_score = 0.75
    elif min_dist == 3 and sld != closest and len(sld) > 3:
        typo_score = 0.30

    # Subdomain depth
    tld_parts = len(tld.split('.')) - 1
    subdomain_depth = max(0, dots - tld_parts - 1)

    # Boolean flags
    has_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0
    has_port = 1 if re.search(r':\d+', raw) else 0
    has_at = 1 if '@' in raw else 0
    special = sum(1 for c in domain if c not in string.ascii_lowercase + string.digits + '.-')
    is_white = 1 if domain in WHITELIST else 0

    return {
        "domain_length":        len(domain),
        "sld_length":           len(sld),
        "shannon_entropy":      round(shannon_entropy(sld), 4),
        "digit_ratio":          round(digits / max(1, len(clean)), 4),
        "hyphen_count":         hyphens,
        "dot_count":            dots,
        "vowel_deviation":      round(vow_deviation, 4),
        "consonant_cluster":    max_consonant,
        "unique_char_ratio":    round(unique_chars / max(1, len(clean)), 4),
        "numeric_sequence":     max_numeric,
        "tld_abuse_score":      round(tld_score, 4),
        "phish_keyword_score":  round(phish_score, 4),
        "brand_match_score":    round(brand_score, 4),
        "typosquat_score":      round(typo_score, 4),
        "subdomain_depth":      subdomain_depth,
        "has_ip":               has_ip,
        "hex_char_ratio":       round(hex_ratio, 4),
        "ngram_score":          round(ngram_score(domain), 4),
        "has_at_symbol":        has_at,
        "has_port":             has_port,
        "special_char_count":   special,
        "is_whitelisted":       is_white,
        # metadata (not used as features)
        "_domain":              domain,
        "_sld":                 sld,
        "_tld":                 tld,
        "_found_kw":            found_kw,
        "_found_brands":        found_brands,
        "_closest_brand":       closest,
        "_min_dist":            min_dist,
    }


import string  # needed for special_char_count