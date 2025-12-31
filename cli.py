# cli.py
import os
import sys
import json
import argparse
import time
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from jinja2 import Environment, FileSystemLoader

from .core import get_file_info
from .virustotal import scan_file_with_virustotal
from .yara_scan import scan_with_yara

console = Console()

# Optional imports (fail gracefully)
try:
    from .capa_scan import scan_with_capa
    CAPA_AVAILABLE = True
except ImportError:
    CAPA_AVAILABLE = False
    console.print("[yellow]CAPA not available (install mandiant-capa)[/]")

try:
    from .hybrid_analysis import scan_hybrid_analysis
    HA_AVAILABLE = True
except ImportError:
    HA_AVAILABLE = False

def generate_html_report(report: dict, output_path: Path):
    template_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.html")

    size_mb = report["file_info"]["size_bytes"] / (1024 * 1024)

    vt_stats = None
    if report.get("virustotal"):
        attrs = report["virustotal"].get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.get(k, 0) for k in ["malicious", "suspicious", "harmless", "undetected", "timeout", "failure"])
        flagged_engines = []
        for engine, res in attrs.get("last_analysis_results", {}).items():
            if res.get("category") in ("malicious", "suspicious"):
                flagged_engines.append((engine, res.get("result", "Unknown")))
        vt_stats = {
            "flagged": flagged,
            "total": total,
            "flagged_engines": flagged_engines
        }

    capa_capabilities = report.get("capa", {}).get("capabilities", []) if report.get("capa") else []

    ha_summary = None
    if report.get("hybrid_analysis"):
        ha = report["hybrid_analysis"]
        ha_summary = {
            "verdict": ha.get("verdict", "N/A"),
            "threat_score": ha.get("threat_score", 0),
            "threats": ha.get("threats", [])[:10]
        }

    html_content = template.render(
        file=report["file_info"]["file"],
        sha256=report["file_info"]["sha256"],
        size_mb=size_mb,
        risk_score=report["fp_risk"]["score"],
        risk_reasons=report["fp_risk"]["reasons"],
        yara_matches=report.get("yara_matches"),
        vt_stats=vt_stats,
        capa_capabilities=capa_capabilities,
        ha_summary=ha_summary,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    html_path = output_path.with_suffix(".html")
    html_path.write_text(html_content)
    console.print(f"[green]HTML report saved:[/] {html_path}")

def process_file(filepath: str, config: dict) -> dict:
    info = get_file_info(filepath)
    console.print(f"\n[bold cyan]Processing:[/] {info['file']} ({info['size_bytes']/1024/1024:.1f} MB)")

    yara_matches = scan_with_yara(filepath) or []

    capa_data = None
    if CAPA_AVAILABLE:
        capa_data = scan_with_capa(filepath)

    vt_data = None
    if config.get("virustotal_api_key"):
        vt_data = scan_file_with_virustotal(filepath, config["virustotal_api_key"])

    ha_data = None
    if HA_AVAILABLE and config.get("hybrid_analysis_api_key"):
        try:
            ha_data = scan_hybrid_analysis(filepath, config["hybrid_analysis_api_key"])
        except Exception as e:
            console.print(f"[yellow]Hybrid Analysis failed: {e}[/]")

    # False Positive Risk Scoring
    risk_reasons = []
    if any("UPX" in m for m in yara_matches):
        risk_reasons.append("UPX packer")
    if info["pe"].get("entropy", 0) > 7.0:
        risk_reasons.append("High section entropy")
    if capa_data and any("encryption" in str(c.get("namespace","")).lower() for c in capa_data.get("capabilities", [])):
        risk_reasons.append("Encryption capabilities")
    if capa_data and any("packer" in str(c.get("name","")).lower() for c in capa_data.get("capabilities", [])):
        risk_reasons.append("Packer capabilities")
    risk_score = min(100, len(risk_reasons) * 25)

    report = {
        "file_info": info,
        "yara_matches": yara_matches,
        "virustotal": vt_data,
        "capa": capa_data,
        "hybrid_analysis": ha_data,
        "fp_risk": {
            "score": risk_score,
            "reasons": risk_reasons
        },
        "generated_at": datetime.now().isoformat()
    }
    return report

def main():
    parser = argparse.ArgumentParser(description="Advanced AV False Positive Tester")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Scan files or directories")
    scan_p.add_argument("paths", nargs="+", help="Files or directories to scan")
    scan_p.add_argument("--output-dir", default="reports", help="Directory for JSON + HTML reports")

    args = parser.parse_args()

    if args.command == "scan":
        output_dir = Path(args.output_dir)
        output_dir.mkdir(exist_ok=True)

        if not Path("config.json").exists():
            console.print("[red]Missing config.json![/]")
            sys.exit(1)

        with open("config.json") as f:
            config = json.load(f)

        files_to_scan = []
        for p in args.paths:
            path = Path(p)
            if path.is_file() and path.suffix.lower() in {".exe", ".dll", ".scr"}:
                files_to_scan.append(path)
            elif path.is_dir():
                files_to_scan.extend(path.rglob("*.exe"))
                files_to_scan.extend(path.rglob("*.dll"))

        if not files_to_scan:
            console.print("[red]No executable files found.[/]")
            return

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning files...", total=len(files_to_scan))

            for file_path in files_to_scan:
                try:
                    report = process_file(str(file_path), config)

                    json_path = output_dir / f"{report['file_info']['sha256']}.json"
                    json_path.write_text(json.dumps(report, indent=2))
                    console.print(f"[green]JSON saved:[/] {json_path}")

                    generate_html_report(report, json_path)

                except Exception as e:
                    console.print(f"[red]Error processing {file_path}: {e}[/]")

                progress.advance(task)

        console.print("\n[bold green]All scans completed![/]")

if __name__ == "__main__":
    main()
