# AV False Positive Tester

A command-line tool to help **legitimate software vendors** detect when their clean binaries are **falsely flagged** by antivirus engines via public APIs (VirusTotal, MetaDefender).

⚠️ **Ethical Use Only**  
This tool is for **non-malicious executables** (e.g., installers, utilities, business software). Do **not** submit malware, packed binaries, or obfuscated code.

🔗 Learn more: [Data Encoder – Ethical AV False Positive Protection](https://data-encoder.com)

## Features
- Submit files to VirusTotal (free tier supported)
- Submit files to MetaDefender Cloud (requires API key)
- Generate JSON/CSV reports of detection count and engine names
- Compare results across scans (e.g., before/after signing)
- Built-in rate-limiting to respect API terms

## Requirements
- Python 3.8+
- `requests`
- VirusTotal API key (free at https://virustotal.com)
- (Optional) MetaDefender API key (https://metadefender.opswat.com)

## Setup
```bash
git clone https://github.com/yourname/av-false-positive-tester.git
cd av-false-positive-tester
pip install -r requirements.txt
