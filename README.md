# 🛡️ Protection From Phishing

A **powerful rule-based phishing email detector** written in pure Python.

No machine learning, no external dataset, no heavy dependencies — just effective rules that actually work.

> ⚠️ **Disclaimer**: For educational and authorized testing only. Do not analyze emails or systems you do not own or have permission to test.

---

## ✨ Features

- Detects suspicious keywords commonly used in phishing
- Detects urgency language ("act now", "immediately", etc.)
- Extracts and analyzes URLs for:
  - Suspicious TLDs
  - URL shorteners
  - Raw IP addresses
  - Excessively long URLs
  - Too many subdomains
- Checks for poor writing style (excessive CAPS, !!, etc.)
- Gives a clear **Risk Score (0-100)** and verdict

---

## 🚀 Usage

### Option 1 — Paste email content
```bash
python email_phishing_detector.py
```
Then paste the email and press `Ctrl+D` (Linux/Mac) or `Ctrl+Z` (Windows).

### Option 2 — Analyze a text file
```bash
python email_phishing_detector.py email.txt
```

---

## 📊 Example Output

```
RISK SCORE: 75/100
VERDICT   : HIGH RISK - Likely Phishing
```

---

## 📁 Project Structure

```
protection-from-/
├── email_phishing_detector.py   # Main detector (fully working)
├── README.md
└── .gitignore
```

---

## 📚 Why this version is better

- Works immediately (no dataset needed)
- No external ML libraries required
- Transparent rules you can understand and improve
- Practical for real learning and demos

---

## 🔗 Related Projects

- [link-security-analyzer](https://github.com/Guruprasad1782011/link-security-analyzer) — Website security scanner
- [security-learning-path](https://github.com/Guruprasad1782011/security-learning-path) — Learning roadmap

---

**Built for learning ethical security practices.**
