import re
import urllib.parse

from config import (
    LEGITIMATE_DOMAINS,
    SUSPICIOUS_TLDS
)

def analyze_url(url):
    flags = []
    score = 0

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()
    except Exception:
        return {"score": 100, "flags": ["Invalid URL format"], "verdict": "phishing"}

    # HTTP (not HTTPS)
    if parsed.scheme == 'http':
        flags.append("Uses HTTP instead of HTTPS (unencrypted)")
        score += 15

    # IP address instead of domain
    if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        flags.append("Uses raw IP address instead of domain name")
        score += 35

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"Uses suspicious TLD: {tld}")
            score += 25
            break

    # URL shorteners
    for shortener in ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly']:
        if shortener in domain:
            flags.append(f"Uses URL shortener ({shortener}) — hides true destination")
            score += 20
            break

    # @ symbol in URL
    if '@' in full:
        flags.append("Contains @ symbol — may redirect to malicious host")
        score += 30

    # Excessive hyphens
    hyphen_count = domain.count('-')
    if hyphen_count >= 3:
        flags.append(f"Domain has {hyphen_count} hyphens — common in phishing domains")
        score += 15

    # Brand name in subdomain/path (not the actual domain)
    brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'bank', 'chase']
    for brand in brands:
        if brand in domain and not domain.startswith(brand + '.') and not domain == brand + '.com':
            flags.append(f"Contains '{brand}' but may not be the real site")
            score += 30
            break

    # Long domain
    if len(domain) > 50:
        flags.append(f"Unusually long domain name ({len(domain)} chars)")
        score += 10

    # Multiple subdomains
    subdomain_parts = domain.split('.')
    if len(subdomain_parts) > 4:
        flags.append(f"Deeply nested subdomains ({len(subdomain_parts)} levels)")
        score += 15

    # Suspicious keywords in path/query
    for kw in ['login', 'verify', 'account', 'secure', 'update', 'signin', 'password']:
        if kw in path:
            flags.append(f"Path contains suspicious keyword: '{kw}'")
            score += 10
            break

    # Check if it looks like a legit domain being spoofed
    for legit in LEGITIMATE_DOMAINS:
        legit_base = legit.split('.')[0]
        if legit_base in domain and legit not in domain:
            flags.append(f"May be impersonating {legit}")
            score += 25
            break

    score = min(score, 100)
    verdict = "safe" if score < 25 else ("suspicious" if score < 55 else "phishing")
    return {"score": score, "flags": flags, "verdict": verdict}