# virustotal.py
import time
import requests

VT_API_BASE = "https://www.virustotal.com/api/v3"
 
def get_virustotal_report(file_hash, api_key):
    url = f"{VT_API_BASE}/files/{file_hash}"
    headers = {"x-apikey": api_key}
    return requests.get(url, headers=headers)

def upload_file_for_analysis(filepath, api_key):
    url = f"{VT_API_BASE}/files"
    headers = {"x-apikey": api_key}
    with open(filepath, 'rb') as f:
        files = {'file': f}
        return requests.post(url, headers=headers, files=files)

def get_analysis_report(analysis_id, api_key):
    url = f"{VT_API_BASE}/analyses/{analysis_id}"
    headers = {"x-apikey": api_key}
    return requests.get(url, headers=headers)

def scan_file_with_virustotal(filepath, api_key, wait_time=15):
    from .core import sha256_file

    file_hash = sha256_file(filepath)
    print(f"[VT] Checking hash: {file_hash}")

    resp = get_virustotal_report(file_hash, api_key)
    if resp.status_code == 200:
        print("[VT] ✅ File found in VirusTotal database.")
        return resp.json()
    elif resp.status_code == 404:
        print("[VT] ❓ File not found. Uploading for analysis...")
        upload_resp = upload_file_for_analysis(filepath, api_key)
        if upload_resp.status_code == 200:
            analysis_id = upload_resp.json()['data']['id']
            print(f"[VT] 📤 Upload OK. Analysis ID: {analysis_id}")
            print(f"[VT] ⏳ Waiting {wait_time} seconds for analysis...")
            time.sleep(wait_time)
            result_resp = get_analysis_report(analysis_id, api_key)
            if result_resp.status_code == 200:
                return result_resp.json()
            else:
                raise Exception(f"[VT] Failed to fetch analysis: {result_resp.status_code} – {result_resp.text}")
        else:
            raise Exception(f"[VT] Upload failed: {upload_resp.status_code} – {upload_resp.text}")
    else:
        raise Exception(f"[VT] API error: {resp.status_code} – {resp.text}")
