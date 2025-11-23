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
**Configuration**
1.Copy the example config:
cp config.example.json config.json
2. Edit config.json with your API keys:
{
  "virustotal_api_key": "your_virustotal_api_key_here",
  "metadefender_api_key": null
}
🔒 Never commit your real config.json to Git—it contains secrets!
**Usage**
Scan a single clean EXE:
python scan.py --file my-clean-app.exe --output report_2025.json
View a readable summary:
python report.py --input report_2025.json
**Output Example**
✅ File: my-clean-app.exe
📊 Size: 2.1 MB
🔑 SHA256: a1b2c3d4e5f6...
🔍 VirusTotal: 3 / 70 engines flagged (False Positive?)
   - Flagged by: ALYac, Zillya, MaxSecure
   - Clean by: Microsoft, Kaspersky, Bitdefender, ESET
📄 Report saved: report_2025.json
**Reporting False Positives**
If your legitimate software is incorrectly flagged:

Use this tool to generate evidence
Submit a false positive report to the AV vendor:
**Microsoft Defender:** https://www.microsoft.com/en-us/wdsi/filesubmission
**Kaspersky:** https://virusdesk.kaspersky.com
**ESET:** https://www.eset.com/int/support/submit-suspicious-file/
**Others:** Check each vendor’s official FP reporting page
**License**
MIT License – Free to use in personal and commercial projects.

**Disclaimer**
This tool does not modify, encrypt, obfuscate, or protect your binary in any way. It only queries public, documented APIs for analysis results.

Misuse (e.g., scanning malware or violating API terms) is strictly prohibited and may result in account bans or legal action.

This project is aligned with ethical software development and is not intended for evasion, bypassing, or offensive security purposes.
