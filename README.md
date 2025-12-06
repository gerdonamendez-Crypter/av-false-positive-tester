# AV False Positive Tester  
# AV 误报检测工具

A command-line tool to help **legitimate software vendors** detect when their clean binaries are **falsely flagged** by antivirus engines via public APIs (VirusTotal, MetaDefender).  
一款命令行工具，帮助**合法软件开发者**通过公共 API（如 VirusTotal、MetaDefender）检测其干净的二进制文件是否被杀毒引擎**错误标记为恶意软件**。

⚠️ **Ethical Use Only**  
⚠️ **仅限合法用途**  
This tool is for **non-malicious executables** (e.g., installers, utilities, business software). Do **not** submit malware, packed binaries, or obfuscated code.  
本工具仅适用于**非恶意可执行文件**（例如安装程序、工具软件、商业应用）。**禁止**提交恶意软件、加壳文件或混淆代码。


🔗 了解更多：[Data Encoder – 合规的 AV 误报防护方案](https://data-encoder.com)

## Features / 功能特点
- Submit files to VirusTotal (free tier supported)  
  支持向 VirusTotal 提交文件（兼容免费配额）
- Submit files to MetaDefender Cloud (requires API key)  
  支持向 MetaDefender Cloud 提交文件（需 API 密钥）
- Generate JSON reports of detection results  
  自动生成检测结果的 JSON 报告
- Display human-readable summaries of flagged engines  
  以可读格式展示被标记的杀毒引擎列表
- Helps document false positives for vendor dispute submissions  
  协助整理误报证据，用于向杀毒厂商申诉

## Requirements / 环境要求
- Python 3.8+
- `requests` library
- 免费的 [VirusTotal API 密钥](https://virustotal.com)
- （可选）[MetaDefender API 密钥](https://metadefender.opswat.com)
## Usage / 使用方法
Scan a file:
 
python cli.py scan --file your-clean-app.exe --output report.json
Example output:
✅ File: installer.exe
📊 Size: 3.2 MB
🔑 SHA256: a1b2c3...f9
🔍 VirusTotal: 2 / 70 engines flagged
   - Flagged by:
     • WindowsDefender: Trojan:Win32/Fuery.B!cl
     • ClamAV: Win.Trojan.FakeInstaller-123
🛡️ YARA Matches:
   • UPX_Packer
## Ethical & Legal Notice / 合规声明
This tool is intended only for software developers to validate the reputation of their own legitimate software.
Do not use it to:

Test malware or exploit payloads
Evaluate the effectiveness of FUD crypters or obfuscators
Bypass security controls for malicious purposes
Misuse of VirusTotal or this tool may result in API key revocation or legal action.

🔗 Learn more: [Data Encoder – Ethical AV False Positive Protection](https://data-encoder.com)  
- 本工具仅限软件开发者验证自身合法程序的信誉状态。
严禁用于：

测试恶意软件或攻击载荷
评估“免杀加密器”或混淆工具的有效性
为恶意目的绕过安全检测
滥用 VirusTotal 或本工具可能导致 API 密钥被封禁或承担法律责任.

## Setup / 安装步骤

```bash
git clone https://github.com/gerdonamendez-Crypter/av-false-positive-tester.git
cd av-false-positive-tester
pip install -r requirements.txt


