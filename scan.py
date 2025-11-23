import os
import sys
import time
import json
import hashlib
import argparse
import requests

def sha256_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def scan_virustotal(file_path, api_key):
    print(f"[VT] Checking if file already exists...")
    file_hash = sha256_file(file_path)

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers)

    if resp.status_code == 200:
        print("[VT] File found in database. Fetching report.")
        return resp.json()
    elif resp.status_code == 404:
        print("[VT] File not found. Uploading...")
        with open(file_path, 'rb') as f:
            upload_url = "https://www.virustotal.com/api/v3/files"
            files = {'file': f}
            resp = requests.post(upload_url, headers=headers, files=files)
            if resp.status_code == 200:
                analysis_id = resp.json()['data']['id']
                print(f"[VT] Upload OK. Analysis ID: {analysis_id}")
                time.sleep(15)
                result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                result = requests.get(result_url, headers=headers)
                if result.status_code == 200:
                    return result.json()
                else:
                    raise Exception(f"[VT] Failed to get analysis: {result.status_code}")
            else:
                raise Exception(f"[VT] Upload failed: {resp.status_code}")
    else:
        raise Exception(f"[VT] API error: {resp.status_code}")

def save_report(data, output_path):
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"[✓] Report saved to {output_path}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', required=True, help='Path to clean binary')
    parser.add_argument('--output', default='report.json', help='Output report path')
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print("[!] File not found.")
        sys.exit(1)

    if not os.path.exists('config.json'):
        print("[!] Create config.json from config.example.json")
        sys.exit(1)

    with open('config.json') as f:
        config = json.load(f)

    vt_key = config.get('virustotal_api_key')
    if not vt_key:
        print("[!] Missing virustotal_api_key in config.json")
        sys.exit(1)

    try:
        vt_report = scan_virustotal(args.file, vt_key)
        final_report = {
            "file": os.path.basename(args.file),
            "size_bytes": os.path.getsize(args.file),
            "sha256": sha256_file(args.file),
            "virustotal": vt_report,
            "metadefender": None
        }
        save_report(final_report, args.output)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
