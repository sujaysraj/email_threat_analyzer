# Email Header Threat Analyzer

A Python tool for analyzing raw email headers and identifying potential threats. It extracts key header fields, evaluates SPF/DKIM results, identifies sender IP addresses, and checks their reputation using AbuseIPDB.

## Features

- Parses email headers from `.eml` files or raw text files
- Extracts and displays:
  - `From`, `To`, `Return-Path`
  - `SPF`, `DKIM` results
  - Sender IP addresses from `Received:` headers
- Checks IP reputation using the AbuseIPDB API
- Presents readable triage-oriented output

## Setup

1. Clone this repository or copy the files into a folder.
2. Install required Python packages:
   ```bash
   pip install requests
   pip install re
   pip install os
   pip install dotenv
3. Get a free API key from AbuseIPDB and save it in .env
4. Save a full email header in a file samples/sample.txt

## Usage

Place a raw email header or full .eml file in the samples/ folder. Then run:
```
python analyzer.py samples/sample1.txt
```
The script will print:
- Parsed header fields
- Authentication results (SPF/DKIM)
- Sender IPs with reputation status

### Sample Output
```
From: sender@example.com
To: you@example.org
Return-Path: <sender@example.com>
SPF: pass
DKIM: pass
IP Address: 192.0.2.1 (Clean)
```

## Notes
- The tool works with .eml or .txt files containing email headers.
- AbuseIPDB requests are rate-limited for free accounts.
- The tool does not send or upload full email content unless extended to do so.

## License
MIT License
