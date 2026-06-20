import re

from config import SUSPICIOUS_KEYWORDS
from analyzers.url_analyzer import analyze_url

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