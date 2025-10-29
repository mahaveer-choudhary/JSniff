
# 🔍 JavaScript Secret Scanner

A Python tool for scanning JavaScript files in web applications to detect exposed API keys, tokens, secrets, and credentials using powerful regex-based pattern matching.

## Features

- Automatic JavaScript Discovery – Extracts and scans all `.js` files linked in a web page
- Regex-Based Secret Detection – Includes 100+ built-in regex patterns for various API keys and tokens
- Custom Headers – Add custom headers (like Authorization or Cookies) to bypass restrictions
- Random User-Agent Rotation – Uses a random User-Agent for each scan request
- Colorized Terminal Output – Easily spot detected secrets in colored output
- Handles Obfuscated JS – Beautifies JavaScript for more accurate pattern matching


## 🧠 How it works

- Takes a target URL as input

- Fetches the page and extracts all `.js` file URLs

- Sends requests to each JavaScript file

- Beautifies and scans the content using regex patterns

- Prints matches (if any) with the name of the detected secret
## Installation

Clone the repository and install the packages 

```bash
git clone github.com/mahaveer-choudhary/secret-scanner
```
```bash
cd secret-scanner
```
```bash
pip install -r requirements.txt --break-system-packages
```

## 💻 Usage
Check help menu : 
```bash
python3 main.py -h
```
Run the scanner using : 

```bash
python3 main.py --url https://example.com
```

To include custom headers (for authentication or bypassing)
```bash
python3 main.py -u https://example.com -H Authorization "Bearer YOUR_TOKEN"
```

## 🧩 Example Output 
```bash
[+] Connected Successfully with https://example.com
[!] Extracting JavaScript Files from https://example.com
[+] 3 file(s) found

[!] Scanning https://example.com/static/js/main.js

 Google API found in https://example.com/static/js/main.js: ['AIzaSyD3...']

 Slack Webhook found in https://example.com/static/js/app.js: ['https://hooks.slack.com/services/...']

```
## ⚠️ Disclaimer

This project is intended for educational and ethical security testing purposes only.
Do not use this tool on websites without proper authorization.
The author is not responsible for any misuse or damage caused.
