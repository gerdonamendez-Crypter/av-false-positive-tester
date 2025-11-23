import json
import argparse
import sys

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    args = parser.parse_args()

    with open(args.input) as f:
        data = json.load(f)

    print(f"✅ File: {data['file']}")
    print(f"📊 Size: {data['size_bytes'] / (1024*1024):.1f} MB")
    print(f"🔑 SHA256: {data['sha256'][:16]}...")

    vt = data.get('virustotal', {}).get('data', {}).get('attributes', {})
    if 'last_analysis_stats' in vt:
        stats = vt['last_analysis_stats']
        total = sum(stats.get(k, 0) for k in ['malicious', 'suspicious', 'undetected', 'harmless'])
        flagged = stats.get('malicious', 0) + stats.get('suspicious', 0)
        print(f"🔍 VirusTotal: {flagged} / {total} engines flagged")

        if flagged > 0:
            print("   - Flagged by:")
            for engine, result in vt.get('last_analysis_results', {}).items():
                if result.get('category') in ['malicious', 'suspicious']:
                    print(f"     • {engine}: {result['result']}")
        else:
            print("   - Clean on all engines ✅")
    else:
        print("[!] No VirusTotal data found")

if __name__ == '__main__':
    main()
