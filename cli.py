# cli.py
import os
import sys
import json
import argparse
from .core import get_file_info
from .virustotal import scan_file_with_virustotal

def scan_command(args):
    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)
 
    if not os.path.exists('config.json'):
        print("[!] Missing config.json. Create it from config.example.json")
        sys.exit(1)

    with open('config.json') as f:
        config = json.load(f)

    api_key = config.get('virustotal_api_key')
    if not api_key:
        print("[!] Missing 'virustotal_api_key' in config.json")
        sys.exit(1)

    try:
        file_info = get_file_info(args.file)
        print(f"[INFO] Analyzing: {file_info['file']} ({file_info['size_bytes']} bytes)")

        # Optional YARA scan
        yara_matches = None
        try:
            from .yara_scan import scan_with_yara
            yara_matches = scan_with_yara(args.file)
            if yara_matches is not None:
                status = ', '.join(yara_matches) if yara_matches else 'None'
                print(f"[🔍] YARA matches: {status}")
        except Exception as e:
            print(f"[!] YARA scan failed: {e}")

        # VirusTotal scan
        vt_data = scan_file_with_virustotal(args.file, api_key, wait_time=args.wait)

        # Build final report
        report = {
            "file": file_info["file"],
            "size_bytes": file_info["size_bytes"],
            "sha256": file_info["sha256"],
            "virustotal": vt_data,
            "metadefender": None,
            "yara": {
                "matches": yara_matches,
                "rules_used": "suspicious_files.yar"
            } if yara_matches is not None else None
        }

        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"[✅] Report saved to: {args.output}")

    except Exception as e:
        print(f"[❌] Error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="File Reputation & YARA Analyzer")
    subparsers = parser.add_subparsers(dest='command', help="Commands")

    scan_parser = subparsers.add_parser('scan', help='Scan file with VirusTotal + YARA')
    scan_parser.add_argument('--file', required=True, help='File to analyze')
    scan_parser.add_argument('--output', default='report.json', help='Report output path')
    scan_parser.add_argument('--wait', type=int, default=15, help='Wait time after upload (default: 15s)')

    view_parser = subparsers.add_parser('view', help='View saved report')
    view_parser.add_argument('--input', required=True, help='Report JSON file')

    args = parser.parse_args()

    if args.command == 'scan':
        scan_command(args)
    elif args.command == 'view':
        from .view import view_report
        view_report(args.input)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
