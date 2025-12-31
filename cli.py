# cli.py
import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from jinja2 import Environment, FileSystemLoader

from .core import get_file_info
from .virustotal import scan_file_with_virustotal
from .yara_scan import scan_with_yara
from .hybrid_analysis import scan_hybrid_analysis

console = Console()

# Optional imports
try:
    from .capa_scan import scan_with_capa
    CAPA_AVAILABLE = True
except ImportError:
    CAPA_AVAILABLE = False
    console.print("[yellow]CAPA not available (pip install mandiant-capa)[/]")

try:
    from .metadefender import scan_metadefender
    MD_AVAILABLE = True
except ImportError:
    MD_AVAILABLE = False

HA_AVAILABLE = True  # Always try, but needs key

def generate_html_report(report: dict, output_path: Path):
    template_dir = Path(__file__).parent / "templates"
    if not template_dir.exists():
        template_dir.mkdir()
        # Create a basic template if missing
        basic_template = """<!DOCTYPE html><html><body><h1>Report for {{ file }}</h1>
        <p>SHA256: {{ sha256 }}</p><p>Size: {{ size_mb }} MB</p>
        <p>Risk Score: {{ risk_score }} ({{ risk_reasons|join(', ') }})</p>
        <!-- Add more sections -->
        </body></html>"""
        (template_dir / "report.html").write_text(basic_template)

    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.html")

    size_mb = report["file_info"]["size_bytes"] / (1024 * 1024)

    # Prepare data for template (expanded)
    html_content = template.render(
        report=report,
        size_mb=round(size_mb, 2),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    html_path = output_path.with_suffix(".html")
    html_path.write_text(html_content)
    console.print(f"[green]HTML report saved:[/] {html_path}")

def process_file(filepath: str, config: dict) -> dict:
    info = get_file_info(filepath)
    console.print(f"\n[bold cyan]Analyzing:[/] {info['file']} ({info['size_bytes']/1024/1024:.2f} MB)")

    yara_matches = scan_with_yara(filepath) or []

    vt_data = None
    if config.get("virustotal_api_key"):
        try:
            vt_data = scan_file_with_virustotal(filepath, config["virustotal_api_key"])
        except Exception as e:
            console.print(f"[yellow]VirusTotal failed: {e}[/]")

    capa_data = None
    if CAPA_AVAILABLE:
        capa_data = scan_with_capa(filepath)

    ha_data = None
    if config.get("hybrid_analysis_api_key") and HA_AVAILABLE:
        try:
            ha_data = scan_hybrid_analysis(filepath, config["hybrid_analysis_api_key"])
        except Exception as e:
            console.print(f"[yellow]Hybrid Analysis failed: {e}[/]")

    md_data = None
    if config.get("metadefender_api_key") and MD_AVAILABLE:
        try:
            md_data = scan_metadefender(filepath, config["metadefender_api_key"])
        except Exception as e:
            console.print(f"[yellow]MetaDefender failed: {e}[/]")

    # Advanced False Positive Risk Scoring (0-100)
    risk_reasons = []
    score = 0

    if any("UPX" in m for m in yara_matches):
        risk_reasons.append("UPX Packer detected")
        score += 30
    if info["pe"].get("entropy", 0) > 7.5:
        risk_reasons.append("High entropy (>7.5)")
        score += 25
    if capa_data:
        caps = capa_data.get("capabilities", [])
        if any("packer" in c.get("name", "").lower() for c in caps):
            risk_reasons.append("Packer capabilities (CAPA)")
            score += 20
        if any("encryption" in c.get("namespace", "").lower() for c in caps):
            risk_reasons.append("Encryption routines")
            score += 15
        if any("anti" in c.get("namespace", "").lower() for c in caps):
            risk_reasons.append("Anti-analysis capabilities")
            score += 30

    suspicious_sections = any(s.lower() in ["upx0", "upx1", ".pack"] for s in info["pe"].get("sections", []))
    if suspicious_sections:
        risk_reasons.append("Suspicious section names")
        score += 20

    risk_score = min(100, score)

    report = {
        "file_info": info,
        "yara_matches": yara_matches,
        "virustotal": vt_data,
        "capa": capa_data,
        "hybrid_analysis": ha_data,
        "metadefender": md_data,
        "fp_risk": {"score": risk_score, "reasons": risk_reasons},
        "generated_at": datetime.now().isoformat()
    }
    return report

def main():
    parser = argparse.ArgumentParser(description="Advanced AV False Positive Tester")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Scan files/directories")
    scan_p.add_argument("paths", nargs="+", help="Files or directories")
    scan_p.add_argument("--output-dir", default="reports", help="Output directory")

    args = parser.parse_args()

    if args.command == "scan":
        output_dir = Path(args.output_dir)
        output_dir.mkdir(exist_ok=True)

        config_path = Path("config.json")
        if not config_path.exists():
            console.print("[red]Missing config.json! Copy from config.example.json and add keys.[/]")
            sys.exit(1)

        config = json.loads(config_path.read_text())
        required_keys = ["virustotal_api_key"]
        missing = [k for k in required_keys if not config.get(k)]
        if missing:
            console.print(f"[red]Missing keys in config.json: {missing}[/]")
            sys.exit(1)

        files_to_scan = []
        for p in args.paths:
            path = Path(p)
            if path.is_file() and path.suffix.lower() in {".exe", ".dll", ".scr"}:
                files_to_scan.append(path)
            elif path.is_dir():
                files_to_scan.extend(list(path.rglob("*.exe")) + list(path.rglob("*.dll")) + list(path.rglob("*.scr")))

        if not files_to_scan:
            console.print("[red]No PE files found.[/]")
            return

        with Progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(files_to_scan))

            for file_path in files_to_scan:
                try:
                    report = process_file(str(file_path), config)

                    json_path = output_dir / f"{report['file_info']['sha256']}.json"
                    json_path.write_text(json.dumps(report, indent=2))
                    console.print(f"[green]JSON report:[/] {json_path}")

                    generate_html_report(report, json_path)

                except Exception as e:
                    console.print(f"[red]Error on {file_path}: {e}[/]")

                progress.advance(task)

        console.print("\n[bold green]Scanning completed![/]")

if __name__ == "__main__":
    main()
