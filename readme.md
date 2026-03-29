### 20+ Features Extracted

| Feature | What it measures | ML Signal |
|---------|-----------------|-----------|
| Shannon Entropy | Character randomness | DGA botnets have high entropy (>3.5 bits) |
| Domain Length | Total domain char count | Abuse domains average 26 chars vs 12 for legit |
| SLD Length | Second-level domain length | Phishing SLDs are longer |
| Digit Ratio | Numbers / total chars | DGA: high digits; legit brands: almost zero |
| Hyphen Count | Number of `-` chars | Phishing stacks keywords with hyphens |
| Vowel Deviation | |vowels/letters - 0.38| | DGA strings deviate from natural language |
| Consonant Cluster | Max consecutive consonants | DGA produces "xkstpq" strings |
| Unique Char Ratio | Unique chars / length | Random DGA domains have low uniqueness |
| Numeric Sequence | Longest digit run | "192168" embedded = IP obfuscation |
| TLD Abuse Score | TLD historical abuse rate | .tk=97%, .ml=95%, .com=5% |
| Phishing Keyword Score | Weighted keyword sum | "login+secure+bank" = high score |
| Brand Match Score | Nepali brand similarity | "esewa" in non-whitelisted domain |
| Typosquat Score | Levenshtein edit distance | "g00gle" → distance 2 from "google" |
| Subdomain Depth | Number of subdomain levels | Deep nesting = obfuscation tactic |
| IP in Domain | Literal IP address | Always suspicious |
| Hex Char Ratio | % of hex-like chars | High = encoded/obfuscated domain |
| N-gram Suspicion | 4-gram phishing match | "logi", "secu", "bank" n-gram hits |
| @ Symbol | URL obfuscation | `bank.com@evil.com` trick |
| Non-std Port | Port number in URL | Legitimate sites don't use ports in domain |
| Dot Count | Total dots | Excessive dots = deep subdomain abuse |

### Weighted Scoring Model

```
Risk Score = Σ (feature_value × feature_weight) / max_possible × 100
```

Example for `ncell-offer.xyz`:
- TLD Abuse Score: 0.72 × 22.0 = **15.84**
- Brand Match Score: 0.80 × 25.0 = **20.00**
- Phishing Keyword Score: 0.12 × 20.0 = **2.40**
- Hyphen Count: 1 × 6.5 = **6.50**
- N-gram Suspicion: 0.3 × 6.0 = **1.80**
- **Total → 46.54 / 120 × 100 = ~38 / HIGH RISK**

###  Classification Modules

1. **Phishing Module** — Keyword-weighted scoring
2. **Malware/DGA Module** — Entropy + digit ratio + TLD + consonant clusters
3. **TLD Risk Module** — Per-TLD abuse probability from Spamhaus/SURBL
4. **Brand Impersonation Module** — 30+ Nepali brands cross-referenced
5. **Typosquatting Module** — Levenshtein distance to popular legitimate domains
6. **Structural Anomaly Module** — Length, hyphens, special chars, subdomains

---

## 📊 Try These Test Cases

| Domain | Expected Result | Why |
|--------|----------------|-----|
| `ncell-offer.xyz` | 🚨 HIGH RISK | Brand + .xyz + keyword |
| `nabilbank-secure-login.tk` | 🚨 HIGH RISK | Brand + keywords + .tk (97%) |
| `g00gle.com` | 🚨 Typosquat | Edit distance 2 from "google" |
| `esewa-verify.ml` | 🚨 HIGH RISK | Brand + "verify" + .ml (95%) |
| `google.com` | ✅ SAFE | Whitelist |
| `nepal.gov.np` | ✅ SAFE | .gov.np = 0% abuse score |
| `xkjd39fk.tk` | 🚨 HIGH RISK | High entropy + DGA pattern + .tk |

---

*🇳🇵 Built in Nepal · For Nepal · For a safer global DNS*
