# AV False Positive Tester

A command-line tool to help **legitimate software vendors** detect when their clean binaries are **falsely flagged** by antivirus engines via public APIs (VirusTotal, MetaDefender).

⚠️ **Ethical Use Only**  
This tool is for **non-malicious executables** (e.g., installers, utilities, business software). Do **not** submit malware, packed binaries, or obfuscated code.

🔗 Learn more: [Data Encoder – Ethical AV False Positive Protection](https://data-encoder.com)

## Features
- Submit files to VirusTotal (free tier supported)
- Submit files to MetaDefender Cloud (requires API key)
- Generate JSON reports of detection results
- Display human-readable summaries of flagged engines
- Helps document false positives for vendor dispute submissions

## Requirements
- Python 3.8+
- `requests` library
- Free [VirusTotal API key](https://virustotal.com)
- (Optional) [MetaDefender API key](https://metadefender.opswat.com)

## Setup

```bash
git clone https://github.com/yourusername/av-false-positive-tester.git
cd av-false-positive-tester
pip install -r requirements.txt

## Configuration
cp config.example.json config.json

## Usage
python scan.py --file my-clean-app.exe --output report_2025.json

## Output Example
✅ File: my-clean-app.exe
📊 Size: 2.1 MB
🔑 SHA256: a1b2c3d4e5f6...
🔍 VirusTotal: 3 / 70 engines flagged (False Positive?)
   - Flagged by: ALYac, Zillya, MaxSecure
   - Clean by: Microsoft, Kaspersky, Bitdefender, ESET
📄 Report saved: report_2025.json
