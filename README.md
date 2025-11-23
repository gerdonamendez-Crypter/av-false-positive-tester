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
## Configuration

1. Copy the example config:
   ```bash
   cp config.example.json config.json
{
  "virustotal_api_key": "your_virustotal_api_key_here",
  "metadefender_api_key": null
}

---

#### ▶️ **Usage**
```md
## Usage

Scan a single clean EXE:
```bash
python scan.py --file my-clean-app.exe --output report_2025.json

---

#### 🖨️ **Output Example**
```md
### Output Example
✅ File: my-clean-app.exe
📊 Size: 2.1 MB
🔑 SHA256: a1b2c3d4e5f6...
🔍 VirusTotal: 3 / 70 engines flagged (False Positive?)

Flagged by: ALYac, Zillya, MaxSecure
Clean by: Microsoft, Kaspersky, Bitdefender, ESET
📄 Report saved: report_2025.json
## Disclaimer

This tool **does not modify, encrypt, obfuscate, or protect** your binary in any way. It only **queries public, documented APIs** for analysis results.

Misuse (e.g., scanning malware or violating API terms) is **strictly prohibited** and may result in account bans or legal action.

This project is aligned with **ethical software development** and is **not intended for evasion, bypassing, or offensive security purposes**.

## Requirements
- Python 3.8+
- `requests` library
- Free [VirusTotal API key](https://virustotal.com)
- (Optional) [MetaDefender API key](https://metadefender.opswat.com)

## Setup

```bash
git clone https://github.com/gerdonamendez-Crypter/av-false-positive-tester.git
cd av-false-positive-tester
pip install -r requirements.txt

