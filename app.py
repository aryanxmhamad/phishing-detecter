from flask import Flask, request, jsonify, send_from_directory
import re
import urllib.parse
import os

app = Flask(__name__, static_folder='static')

# ─────────────────────────────────────────────
# RULE ENGINE
# ─────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    'verify', 'account', 'suspended', 'urgent', 'login', 'update', 'confirm',
    'password', 'bank', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
    'click here', 'act now', 'limited time', 'free', 'winner', 'congratulations',
    'security alert', 'unusual activity', 'billing', 'invoice', 'refund',
    'your account has been', 'dear customer', 'dear user', 'kindly', 'immediately'
]

PHISHING_URL_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',           # IP address as host
    r'(paypal|amazon|apple|google|microsoft|bank).*\.(ru|cn|tk|ml|ga|cf|gq|pw|xyz|top|club)',  # brand + bad tld
    r'@',                                               # @ in URL (redirect trick)
    r'-{3,}',                                           # many hyphens
    r'(login|signin|secure|account|update|verify).*\.(com|net|org)\.',  # subdomain abuse
    r'bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd|cli\.gs|buff\.ly',   # URL shorteners
    r'[a-z0-9]{30,}',                                  # very long random string
]

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.xyz', '.top', '.club', '.ru', '.cn', '.cc', '.ws']

LEGITIMATE_DOMAINS = [
    'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'github.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'paypal.com', 'netflix.com', 'reddit.com', 'wikipedia.org'
]

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


def analyze_email(text):
    flags = []
    score = 0
    text_lower = text.lower()

    # Suspicious keywords
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    if found_keywords:
        flags.append(f"Contains {len(found_keywords)} suspicious keyword(s): {', '.join(found_keywords[:5])}")
        score += min(len(found_keywords) * 6, 30)

    # Urgency language
    urgency_patterns = [
        r'(within|in)\s+\d+\s+(hour|day|minute)',
        r'act\s+(now|immediately|urgently)',
        r'will\s+be\s+(deleted|suspended|closed)',
        r'last\s+(chance|warning|notice)',
        r'expire[sd]?\s+(soon|today|in)',
    ]
    for pat in urgency_patterns:
        if re.search(pat, text_lower):
            flags.append("Uses urgency/threat language to pressure action")
            score += 20
            break

    # Generic greeting
    if re.search(r'dear\s+(customer|user|client|member|account holder)', text_lower):
        flags.append("Uses generic greeting ('Dear Customer') instead of your name")
        score += 15

    # Requests for sensitive info
    sensitive = ['password', 'credit card', 'social security', 'ssn', 'bank account', 'pin', 'cvv']
    for s in sensitive:
        if s in text_lower:
            flags.append(f"Requests sensitive information: '{s}'")
            score += 25
            break

    # URLs in email
    urls = re.findall(r'https?://\S+', text)
    if urls:
        url_results = [analyze_url(u) for u in urls[:3]]
        phish_urls = [r for r in url_results if r['verdict'] == 'phishing']
        susp_urls = [r for r in url_results if r['verdict'] == 'suspicious']
        if phish_urls:
            flags.append(f"Contains {len(phish_urls)} likely phishing URL(s)")
            score += 30
        elif susp_urls:
            flags.append(f"Contains {len(susp_urls)} suspicious URL(s)")
            score += 15

    # Spelling/grammar red flags (common phishing tells)
    bad_phrases = ['kindly', 'do the needful', 'revert back', 'valued customer', 'esteemed']
    for phrase in bad_phrases:
        if phrase in text_lower:
            flags.append(f"Contains phrase common in phishing: '{phrase}'")
            score += 10
            break

    # Too many exclamation marks
    excl_count = text.count('!')
    if excl_count > 3:
        flags.append(f"Excessive exclamation marks ({excl_count}) — common in spam/phishing")
        score += 10

    # Mismatched link text
    link_patterns = re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>', text, re.IGNORECASE)
    for href, label in link_patterns:
        if 'http' in label.lower() and urllib.parse.urlparse(href).netloc not in label:
            flags.append("Link text doesn't match the actual URL destination")
            score += 25
            break

    score = min(score, 100)
    verdict = "safe" if score < 25 else ("suspicious" if score < 55 else "phishing")
    return {"score": score, "flags": flags, "verdict": verdict}


def analyze_html(html):
    flags = []
    score = 0
    html_lower = html.lower()

    # Hidden form fields
    hidden_count = len(re.findall(r'type=["\']hidden["\']', html_lower))
    if hidden_count > 3:
        flags.append(f"Contains {hidden_count} hidden form fields — may harvest data covertly")
        score += 20

    # Password inputs
    if re.search(r'type=["\']password["\']', html_lower):
        flags.append("Contains password input field")
        score += 10

    # Forms posting to external domains
    form_actions = re.findall(r'action=["\']([^"\']+)["\']', html_lower)
    for action in form_actions:
        if action.startswith('http') and not any(ld in action for ld in LEGITIMATE_DOMAINS):
            flags.append(f"Form submits to external/unknown URL: {action[:60]}")
            score += 30
            break

    # Obfuscated JavaScript
    obfusc_patterns = [
        r'eval\s*\(',
        r'unescape\s*\(',
        r'fromcharcode',
        r'\\x[0-9a-f]{2}',
        r'document\.write\(',
    ]
    for pat in obfusc_patterns:
        if re.search(pat, html_lower):
            flags.append(f"Contains potentially obfuscated JavaScript ({pat.replace(r'\\', '')})")
            score += 25
            break

    # Fake login form indicators
    login_keywords = ['username', 'email', 'password', 'sign in', 'log in']
    login_hits = sum(1 for k in login_keywords if k in html_lower)
    if login_hits >= 3:
        flags.append("Appears to contain a login form — verify you're on the real site")
        score += 15

    # iframe from external source
    iframes = re.findall(r'<iframe[^>]+src=["\']([^"\']+)["\']', html_lower)
    for src in iframes:
        if src.startswith('http'):
            flags.append(f"Embeds external iframe: {src[:60]}")
            score += 20
            break

    # Meta refresh redirect
    if re.search(r'<meta[^>]+http-equiv=["\']refresh["\']', html_lower):
        flags.append("Contains auto-redirect (meta refresh) — may send you elsewhere")
        score += 20

    # Suspicious links
    links = re.findall(r'href=["\']([^"\']+)["\']', html_lower)
    bad_links = [l for l in links if any(tld in l for tld in SUSPICIOUS_TLDS)]
    if bad_links:
        flags.append(f"Contains links to suspicious domains ({len(bad_links)} found)")
        score += 20

    score = min(score, 100)
    verdict = "safe" if score < 25 else ("suspicious" if score < 55 else "phishing")
    return {"score": score, "flags": flags, "verdict": verdict}


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    mode = data.get('mode', 'url')
    content = data.get('content', '').strip()

    if not content:
        return jsonify({"error": "No content provided"}), 400

    if mode == 'url':
        result = analyze_url(content)
    elif mode == 'email':
        result = analyze_email(content)
    elif mode == 'html':
        result = analyze_html(content)
    else:
        return jsonify({"error": "Invalid mode"}), 400

    return jsonify(result)


if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
