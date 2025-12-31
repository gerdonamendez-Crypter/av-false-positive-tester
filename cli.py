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

console = Console()

def process_file(filepath, config):
    info = get_file_info(filepath)
    console.print(f"[bold]Scanning:[/] {info['file']} ({info['size_bytes']/1024/1024:.1f} MB)")

    yara_matches = scan_with_yara(filepath)

    vt_data = None
    if config.get('virustotal_api_key'):
        vt_data = scan_file_with_virustotal(filepath, config['virustotal_api_key'])

    md_data = None
    # if config.get('metadefender_api_key'):
    #     md_data = scan_metadefender(filepath, config['metadefender_api_key'])

    report = {
        "file_info": info,
        "yara_matches": yara_matches,
        "virustotal": vt_data,
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

    vt = data.get("virustotal", {}).get("data", {}).get("attributes", {})
    if vt:
        stats = vt["last_analysis_stats"]
        flagged = stats["malicious"] + stats["suspicious"]
        total = stats["harmless"] + stats["undetected"] + flagged + stats.get("timeout", 0)
        console.print(f"[bold blue]VirusTotal:[/] {flagged}/{total} flagged")

        if flagged:
            table = Table(title="Flagged Engines")
            table.add_column("Engine")
            table.add_column("Detection")
            for engine, res in vt["last_analysis_results"].items():
                if res["category"] in ("malicious", "suspicious"):
                    table.add_row(engine, res.get("result", "N/A"))
            console.print(table)

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
                report = process_file(str(file_path), config)
                out_path = Path(args.output_dir) / f"{report['file_info']['sha256']}.json"
                json.dump(report, out_path.open('w'), indent=2)
                console.print(f"[green]Saved:[/] {out_path}")
            except Exception as e:
                console.print(f"[red]Error on {file_path}: {e}[/]")

    elif args.command == 'view':
        view_report(args.report)

if __name__ == '__main__':
    main()
