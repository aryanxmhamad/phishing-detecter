# 🛡️ Phishing Detector

A simple web-based phishing detection tool built with **Python**, **Flask**, and **HTML**. It analyzes URLs, emails, and HTML code to identify common phishing indicators and provides a risk score with a verdict.

---

## Features

- 🔗 Analyze URLs for phishing indicators
- 📧 Analyze email content
- 🌐 Analyze HTML pages
- 📊 Risk score (0–100)
- ✅ Verdict:
  - Safe
  - Suspicious
  - Phishing

---

## Detection Methods

### URL Analysis
- HTTP instead of HTTPS
- Suspicious top-level domains
- URL shorteners
- Raw IP addresses
- Brand impersonation
- Excessive subdomains

### Email Analysis
- Suspicious keywords
- Urgency language
- Generic greetings
- Requests for sensitive information
- Suspicious links

### HTML Analysis
- Hidden form fields
- Password input fields
- External form actions
- Obfuscated JavaScript
- External iframes
- Meta refresh redirects

---

## Project Structure

```
phishing-detector/
│
├── app.py
├── config.py
├── analyzers/
│   ├── url_analyzer.py
│   ├── email_analyzer.py
│   └── html_analyzer.py
│
├── static/
│   └── index.html
│
|
└── README.md
|
|____requirements.txt
|
|
|_____vercel.json

```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YourUsername/phishing-detector.git
cd phishing-detector
```

Install the required packages:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open your browser:

```
http://127.0.0.1:5000
```

---

## Technologies Used

- Python
- Flask
- HTML

---

## Future Improvements

- Machine learning detection
- Domain reputation checks
- WHOIS lookup
- Better UI
- Detection history

---

## Disclaimer

This project is for educational purposes only. It is designed to demonstrate phishing detection techniques and should not be relied upon as the sole method of identifying malicious websites or emails.

---

## Author

**Your Name**

GitHub: https://github.com/YourUsername



