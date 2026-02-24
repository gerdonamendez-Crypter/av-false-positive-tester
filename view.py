# view.py
import json

def view_report(report_path):
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read report: {e}")
        return
 
    print(f"✅ File: {data['file']}")
    print(f"📊 Size: {data['size_bytes'] / (1024*1024):.1f} MB")
    print(f"🔑 SHA256: {data['sha256']}")
 
    vt = data.get('virustotal', {}).get('data', {}).get('attributes', {})
    if 'last_analysis_stats' in vt:
        stats = vt['last_analysis_stats']
        total = sum(stats.get(k, 0) for k in ['malicious', 'suspicious', 'undetected', 'harmless', 'timeout'])
        flagged = stats.get('malicious', 0) + stats.get('suspicious', 0)
        print(f"🔍 VirusTotal: {flagged} / {total} engines flagged")

        if flagged > 0:
            print("   - Flagged by:")
            results = vt.get('last_analysis_results', {})
            for engine, res in results.items():
                if res.get('category') in ('malicious', 'suspicious'):
                    print(f"     • {engine}: {res.get('result', 'N/A')}")
        else:
            print("   - Clean on all engines ✅")
    else:
        print("[!] No VirusTotal data found in report")

    # YARA output
    if "yara" in data and data["yara"] is not None:
        yara_matches = data["yara"].get("matches")
        if yara_matches:
            print("🛡️ YARA Matches:")
            for rule in yara_matches:
                print(f"   • {rule}")
        else:
            print("🛡️ YARA: No matches")
    elif "yara" in data:
        print("🛡️ YARA: Not scanned")
