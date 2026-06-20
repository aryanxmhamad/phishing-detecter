import re

from config import (
    LEGITIMATE_DOMAINS,
    SUSPICIOUS_TLDS
)
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
