#!/usr/bin/env python3
"""
Protection From Phishing
A practical rule-based phishing email detector.
Educational / authorized use only.
"""

import re
import sys
from urllib.parse import urlparse

# ====================== RULES ======================

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify your account", "account suspended", "click here",
    "act now", "limited time", "confirm your identity", "password expired",
    "unusual activity", "secure your account", "update your information",
    "login immediately", "your account will be closed", "wire transfer",
    "bank account", "ssn", "social security", "gift card", "lottery",
    "you have won", "claim your prize", "free money", "bitcoin",
    "crypto wallet", "invoice attached", "payment required"
]

URGENCY_WORDS = [
    "immediately", "urgent", "asap", "right now", "within 24 hours",
    "expires today", "last chance", "act now", "hurry"
]

SUSPICIOUS_TLDS = [".zip", ".review", ".country", ".kim", ".cricket",
                   ".science", ".work", ".party", ".gq", ".ml", ".cf", ".tk"]

SHORTENERS = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
              "is.gd", "buff.ly", "adf.ly", "j.mp"]

# ====================== FUNCTIONS ======================

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
    return re.findall(url_pattern, text, re.IGNORECASE)

def check_suspicious_keywords(text):
    text_lower = text.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_lower]
    return found

def check_urgency(text):
    text_lower = text.lower()
    found = [w for w in URGENCY_WORDS if w in text_lower]
    return found

def check_urls(urls):
    issues = []
    for url in urls:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc.lower()

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                issues.append(f"Suspicious TLD in URL: {url}")

        for short in SHORTENERS:
            if short in domain:
                issues.append(f"URL shortener detected: {url}")

        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            issues.append(f"URL uses raw IP address: {url}")

        if len(url) > 100:
            issues.append(f"Unusually long URL: {url[:60]}...")

        if domain.count('.') >= 3:
            issues.append(f"Many subdomains (possible spoofing): {domain}")

    return issues

def check_grammar_and_style(text):
    issues = []
    if text.count('!') >= 3:
        issues.append("Excessive exclamation marks (!)")
    if text.count('?') >= 3:
        issues.append("Excessive question marks")

    caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
    if len(caps_words) >= 3:
        issues.append(f"Many ALL-CAPS words: {', '.join(caps_words[:5])}")

    return issues

def calculate_score(keyword_hits, urgency_hits, url_issues, style_issues):
    score = 0
    score += len(keyword_hits) * 15
    score += len(urgency_hits) * 10
    score += len(url_issues) * 20
    score += len(style_issues) * 8
    return min(score, 100)

def analyze_email(text):
    print("=" * 65)
    print("  Protection From Phishing - Email Analyzer")
    print("  Educational / Authorized use only")
    print("=" * 65)
    print()

    keyword_hits = check_suspicious_keywords(text)
    urgency_hits = check_urgency(text)
    urls = extract_urls(text)
    url_issues = check_urls(urls)
    style_issues = check_grammar_and_style(text)

    score = calculate_score(keyword_hits, urgency_hits, url_issues, style_issues)

    print("[+] Suspicious Keywords Found:")
    if keyword_hits:
        for kw in keyword_hits:
            print(f"    • {kw}")
    else:
        print("    None")

    print("\n[+] Urgency Indicators:")
    if urgency_hits:
        for w in urgency_hits:
            print(f"    • {w}")
    else:
        print("    None")

    print("\n[+] URLs Detected:")
    if urls:
        for u in urls:
            print(f"    • {u}")
    else:
        print("    None")

    print("\n[+] URL Issues:")
    if url_issues:
        for issue in url_issues:
            print(f"    • {issue}")
    else:
        print("    None")

    print("\n[+] Style / Language Issues:")
    if style_issues:
        for issue in style_issues:
            print(f"    • {issue}")
    else:
        print("    None")

    print("\n" + "-" * 65)
    print(f"  RISK SCORE: {score}/100")

    if score >= 70:
        verdict = "HIGH RISK - Likely Phishing"
    elif score >= 40:
        verdict = "MEDIUM RISK - Suspicious"
    elif score >= 20:
        verdict = "LOW RISK - Some concerns"
    else:
        verdict = "LOW RISK - Appears relatively safe"

    print(f"  VERDICT   : {verdict}")
    print("-" * 65)
    print()
    print("Note: This is a rule-based educational tool. Always verify manually.")
    print("=" * 65)

    return score, verdict

def main():
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r", encoding="utf-8", errors="ignore") as f:
            email_text = f.read()
    else:
        print("Paste the email content below. Press Ctrl+D (Linux/Mac) or Ctrl+Z (Windows) when done:\n")
        email_text = sys.stdin.read()

    if not email_text.strip():
        print("No email content provided.")
        sys.exit(1)

    analyze_email(email_text)

if __name__ == "__main__":
    main()
