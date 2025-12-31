# AV False Positive Tester
# AV 误报检测工具

A powerful command-line tool designed to help **legitimate software developers and vendors** quickly detect when their **clean Windows executables** are falsely flagged by antivirus engines using public scanning services.

一款功能强大的命令行工具，专为**合法软件开发者与厂商**设计，帮助快速检测自家**干净的 Windows 可执行文件**是否被杀毒引擎误报为恶意软件。

Now with **advanced static analysis**, **behavioral capability detection (CAPA)**, **YARA rule matching**, **improved false-positive risk scoring**, and **beautiful HTML reports**.

现已支持**高级静态分析**、**行为能力检测（CAPA）**、**YARA 规则匹配**、**更精准的误报风险评分**以及**美观的 HTML 报告**。

⚠️ **Ethical Use Only / 仅限合法用途**

This tool is intended **exclusively** for **non-malicious, legitimate executables** (e.g., installers, utilities, enterprise tools, commercial software).  
Do **not** use it to submit malware, packed/obfuscated binaries, crypter output, or any harmful code.

本工具**仅限**用于**非恶意、合法的可执行文件**（如安装程序、实用工具、企业软件、商业应用）。  
**严禁**提交恶意软件、加壳/混淆二进制文件、加密器输出或任何有害代码。

Misuse may result in API key revocation or legal consequences.  
滥用可能导致 API 密钥被吊销或承担法律责任。

🔗 Learn more: [Data Encoder – Compliant AV False Positive Protection](https://data-encoder.com)

## Features / 功能特点

- Submit files to **VirusTotal** (supports free tier, including files >32 MB)  
  支持向 **VirusTotal** 提交文件（兼容免费配额，支持 >32 MB 大文件）
- Optional integration with **Hybrid Analysis** and **MetaDefender Cloud**  
  可选集成 **Hybrid Analysis** 与 **MetaDefender Cloud**
- Local **YARA rule scanning** for common false-positive triggers (e.g., UPX packer)  
  本地 **YARA 规则扫描**，检测常见误报诱因（如 UPX 加壳）
- **CAPA** static behavioral analysis (detects packers, encryption, anti-analysis, etc.)  
  **CAPA** 静态行为能力分析（检测加壳、加密、防分析等特征）
- Advanced **False Positive Risk Score** (0–100) with detailed reasons  
  高级**误报风险评分**（0–100 分），并列出具体原因
- Generate **detailed JSON reports** and **beautiful, professional HTML reports**  
  生成详细 **JSON 报告** 与 **美观、专业级 HTML 报告**
- Batch scanning of directories (recursive `.exe`, `.dll`, `.scr`)  
  支持批量扫描目录（递归查找 `.exe`、`.dll`、`.scr`）
- Rich console output with progress bars  
  丰富的控制台输出，带进度条显示

  ## Sample HTML Report / HTML 报告示例
  The generated HTML reports feature:

- File overview with colored risk score badge
- VirusTotal detection statistics and expandable list of flagged engines
- YARA rule matches
- CAPA detected capabilities
- Hybrid Analysis verdict (if enabled)
- Clean, responsive design (works on desktop and mobile)

## Requirements / 环境要求

- Python 3.8+
- Libraries listed in `requirements.txt`

**API Keys Needed / 所需密钥：**
- Free [VirusTotal API key](https://www.virustotal.com/gui/join-us) (required)  
  免费 [VirusTotal API 密钥](https://www.virustotal.com/gui/join-us)（必须）
- Optional: Hybrid Analysis API key (for sandbox verdict)  
  可选：Hybrid Analysis API 密钥（用于沙箱分析）
- Optional: MetaDefender Cloud API key  
  可选：MetaDefender Cloud API 密钥

## Installation / 安装步骤

```bash
git clone https://github.com/gerdonamendez-Crypter/av-false-positive-tester.git
cd av-false-positive-tester
pip install -r requirements.txt
