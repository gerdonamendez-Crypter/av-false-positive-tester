# cli.py
import os
import sys
import json
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table
from .core import get_file_info
from .virustotal import scan_file_with_virustotal
from .yara_scan import scan_with_yara
# from .metadefender import scan_metadefender  # Uncomment if key provided
from .hybrid_analysis import scan_with_hybrid_analysis  # <-- ADD THIS IMPORT

console = Console()

def process_file(filepath, config):
    info = get_file_info(filepath)
    console.print(f"[bold]Scanning:[/] {info['file']} ({info['size_bytes']/1024/1024:.1f} MB)")

    yara_matches = scan_with_yara(filepath)

    vt_data = None
    if config.get('virustotal_api_key'):
        vt_data = scan_file_with_virustotal(filepath, config['virustotal_api_key'])

    ha_data = None
    if config.get('hybrid_analysis_api_key'):
        ha_data = scan_with_hybrid_analysis(filepath, config['hybrid_analysis_api_key'])

    md_data = None
    # if config.get('metadefender_api_key'):
    #     md_data = scan_metadefender(filepath, config['metadefender_api_key'])

    report = {
        "file_info": info,
        "yara_matches": yara_matches,
        "virustotal": vt_data,
        "hybrid_analysis": ha_data,          # <-- ADD TO REPORT
        "metadefender": md_data
    }
    return report

def view_report(report_path):
    with open(report_path) as f:
        data = json.load(f)
    info = data["file_info"]
    console.print(f"[green]File:[/] {info['file']} | SHA256: {info['sha256'][:16]}...")

    if data["yara_matches"]:
        console.print("[yellow]YARA Matches:[/]", ", ".join(data["yara_matches"]))

    # VirusTotal
    vt = data.get("virustotal", {}).get("data", {}).get("attributes", {})
    if vt:
        stats = vt["last_analysis_stats"]
        flagged = stats["malicious"] + stats["suspicious"]
        total = sum(stats.values())
        console.print(f"[bold blue]VirusTotal:[/] {flagged}/{total} flagged")
        if flagged:
            table = Table(title="VT: Flagged Engines")
            table.add_column("Engine")
            table.add_column("Detection")
            for engine, res in vt["last_analysis_results"].items():
                if res["category"] in ("malicious", "suspicious"):
                    table.add_row(engine, res.get("result", "N/A"))
            console.print(table)

    # Hybrid Analysis
    ha = data.get("hybrid_analysis")
    if ha:
        verdict = ha.get("verdict", "N/A")
        threat_score = ha.get("threat_score", "N/A")
        console.print(f"[bold magenta]Hybrid Analysis:[/] Verdict: {verdict} | Threat Score: {threat_score}")
        # Optional: Show scan ID or link
        scan_id = ha.get("id")
        if scan_id:
            console.print(f"[link=https://hybrid-analysis.com/report/{scan_id}]View Full Report[/]")

def main():
    parser = argparse.ArgumentParser(description="Advanced AV False Positive Tester")
    subparsers = parser.add_subparsers(dest='command')
    
    scan_p = subparsers.add_parser('scan')
    scan_p.add_argument('paths', nargs='+', help='Files or directories to scan')
    scan_p.add_argument('--output-dir', default='reports', help='Output directory')
    
    view_p = subparsers.add_parser('view')
    view_p.add_argument('report', help='JSON report file')
    
    args = parser.parse_args()

    if args.command == 'scan':
        os.makedirs(args.output_dir, exist_ok=True)
        with open('config.json') as f:
            config = json.load(f)

        files = []
        for p in args.paths:
            path = Path(p)
            if path.is_file():
                files.append(path)
            elif path.is_dir():
                files.extend(path.rglob('*.exe'))

        for file_path in files:
            try:
                report = process_preprocess(str(file_path), config)  # ❌ TYPO! Fix below
            except Exception as e:
                console.print(f"[red]Error on {file_path}: {e}[/]")
                continue

            out_path = Path(args.output_dir) / f"{report['file_info']['sha256']}.json"
            with out_path.open('w') as f:
                json.dump(report, f, indent=2)
            console.print(f"[green]Saved:[/] {out_path}")

    elif args.command == 'view':
        view_report(args.report)

if __name__ == '__main__':
    main()
