"""
generate_dataset.py
===================
Creates a labeled training dataset of domains.

Labels:
  0 = legitimate
  1 = phishing
  2 = malware/DGA
  3 = spam

In a real production system you would download:
  - PhishTank full dataset: https://www.phishtank.com/developer_info.php
  - SURBL: https://www.surbl.org/
  - Alexa/Tranco top 1M: https://tranco-list.eu/

Here we generate a realistic synthetic dataset that mirrors
the statistical properties found in those real datasets.
"""

import csv
import random
import string
import math
import os

random.seed(42)

# ── Legitimate domains (label 0) ──────────────────────────────────────────────
LEGIT_DOMAINS = [
    # Global
    "google.com","facebook.com","youtube.com","twitter.com","amazon.com",
    "microsoft.com","apple.com","wikipedia.org","github.com","stackoverflow.com",
    "instagram.com","linkedin.com","reddit.com","netflix.com","cloudflare.com",
    "dropbox.com","spotify.com","airbnb.com","zoom.us","slack.com",
    "stripe.com","shopify.com","salesforce.com","adobe.com","paypal.com",
    # Nepali legitimate
    "nepal.gov.np","mof.gov.np","moha.gov.np","election.gov.np","nta.gov.np",
    "passport.gov.np","immigration.gov.np","parliament.gov.np","nrb.org.np",
    "nabilbank.com","nicasiabank.com","esewa.com.np","khalti.com",
    "ncell.axiata.com","ntc.net.np","worldlink.com.np","subisu.net.np",
    "himalayanbank.com","primebank.com.np","siddhartha.com.np",
    "everestbank.com.np","citizenbank.com.np","ictfoundation.org.np",
    "ku.edu.np","ioe.edu.np","tU.edu.np","paschimanchal.edu.np",
]

def make_legit_variant(base):
    """Create realistic looking legitimate domains"""
    parts = base.split(".")
    prefixes = ["www","mail","blog","shop","app","api","help","support","my","secure"]
    if random.random() < 0.3:
        return random.choice(prefixes) + "." + base
    return base

LEGIT = []
for d in LEGIT_DOMAINS:
    LEGIT.append(d)
    for _ in range(random.randint(1, 3)):
        LEGIT.append(make_legit_variant(d))

# Add more realistic legit domains
WORDS = ["news","bank","shop","tech","media","cloud","digital","smart","easy","fast",
         "nepal","kathmandu","pokhara","himalaya","sagarmatha","bagmati","gandaki"]
LEGIT_TLDS = [".com",".org",".net",".com.np",".org.np",".edu.np",".gov.np",".io",".co"]
for _ in range(200):
    w1 = random.choice(WORDS)
    w2 = random.choice(WORDS)
    tld = random.choice(LEGIT_TLDS)
    LEGIT.append(f"{w1}{w2}{tld}")

# ── Phishing domains (label 1) ────────────────────────────────────────────────
NEPAL_BRANDS = ["ncell","esewa","khalti","nabilbank","nicasia","nrb","ntc",
                "himalayan","worldlink","subisu","fonepay","connectips"]
PHISH_KEYWORDS = ["login","secure","verify","account","update","signin","banking",
                  "payment","wallet","confirm","alert","suspended","recover","free",
                  "offer","recharge","apply","renew","bonus","prize","win","claim"]
PHISH_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".pw",".top",".click",
              ".online",".site",".icu",".sbs",".cam",".cyou"]

def make_phishing():
    brand = random.choice(NEPAL_BRANDS)
    kw1 = random.choice(PHISH_KEYWORDS)
    kw2 = random.choice(PHISH_KEYWORDS)
    tld = random.choice(PHISH_TLDS)
    patterns = [
        f"{brand}-{kw1}{tld}",
        f"{brand}-{kw1}-{kw2}{tld}",
        f"{kw1}-{brand}-nepal{tld}",
        f"secure-{brand}-{kw1}{tld}",
        f"{brand}{kw1}nepal{tld}",
        f"my{brand}-{kw1}{tld}",
        f"{brand}-nepal-{kw1}{tld}",
        f"official-{brand}-{kw1}{tld}",
    ]
    return random.choice(patterns)

PHISHING = [make_phishing() for _ in range(400)]

# Add typosquatted domains
POPULAR = ["google","facebook","youtube","ncell","esewa","nabil","khalti"]
TYPO_TLDS = [".com",".net",".org"] + PHISH_TLDS
def make_typo(word):
    ops = [
        lambda w: w[:1]+"0"+w[2:] if len(w)>2 else w+"0",  # o→0
        lambda w: w+"s",
        lambda w: w+"-"+w,
        lambda w: w[:len(w)//2]+"l"+w[len(w)//2:],         # insert l
        lambda w: w.replace("a","4"),
        lambda w: w+"l",
        lambda w: "my"+w,
    ]
    op = random.choice(ops)
    return op(word) + random.choice(TYPO_TLDS)

for pop in POPULAR:
    for _ in range(15):
        PHISHING.append(make_typo(pop))

# ── Malware / DGA domains (label 2) ───────────────────────────────────────────
def make_dga():
    """Simulate DGA (Domain Generation Algorithm) domains — used by botnets.
    Key property: algorithmically generated → high entropy, unnatural char distribution."""
    length = random.randint(10, 24)
    # DGA uses mostly consonants and digits with low vowel ratio
    chars = string.ascii_lowercase + string.digits
    # Weight toward consonants (DGA characteristic)
    consonants = "bcdfghjklmnpqrstvwxyz0123456789"
    vowels_set = "aeiou"
    sld = ""
    for _ in range(length):
        if random.random() < 0.15:   # only 15% vowels (vs natural 38%)
            sld += random.choice(vowels_set)
        else:
            sld += random.choice(consonants)
    tld = random.choice(PHISH_TLDS + [".com",".net"])
    return sld + tld

MALWARE = [make_dga() for _ in range(350)]

# Add known-pattern malware domains
for _ in range(100):
    prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(8,16)))
    num = random.randint(100, 9999)
    tld = random.choice(PHISH_TLDS)
    MALWARE.append(f"{prefix}{num}{tld}")

# ── Spam domains (label 3) ────────────────────────────────────────────────────
SPAM_WORDS = ["deal","discount","offer","sale","buy","cheap","free","win","prize",
              "earn","money","job","work","abroad","qatar","malaysia","korea",
              "remittance","send","transfer","visa","travel"]
def make_spam():
    w1 = random.choice(SPAM_WORDS)
    w2 = random.choice(SPAM_WORDS)
    n = random.randint(1, 999)
    tld = random.choice(PHISH_TLDS + [".info",".biz"])
    patterns = [
        f"{w1}{w2}{n}{tld}",
        f"best-{w1}-{w2}{tld}",
        f"{w1}-nepal-{n}{tld}",
        f"top{w1}{w2}{tld}",
    ]
    return random.choice(patterns)

SPAM = [make_spam() for _ in range(300)]

# ── Assemble dataset ──────────────────────────────────────────────────────────
rows = []
for d in LEGIT:
    rows.append({"domain": d.lower().strip(), "label": 0, "label_name": "legitimate"})
for d in PHISHING:
    rows.append({"domain": d.lower().strip(), "label": 1, "label_name": "phishing"})
for d in MALWARE:
    rows.append({"domain": d.lower().strip(), "label": 2, "label_name": "malware_dga"})
for d in SPAM:
    rows.append({"domain": d.lower().strip(), "label": 3, "label_name": "spam"})

random.shuffle(rows)

os.makedirs("data", exist_ok=True)
with open("data/domains.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["domain","label","label_name"])
    writer.writeheader()
    writer.writerows(rows)

print(f"✅ Dataset generated: {len(rows)} domains")
print(f"   Legitimate : {sum(1 for r in rows if r['label']==0)}")
print(f"   Phishing   : {sum(1 for r in rows if r['label']==1)}")
print(f"   Malware/DGA: {sum(1 for r in rows if r['label']==2)}")
print(f"   Spam       : {sum(1 for r in rows if r['label']==3)}")
print(f"   Saved to   : data/domains.csv")