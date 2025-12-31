# hybrid_analysis.py
import requests
from tenacity import retry, stop_after_attempt, wait_exponential

HA_BASE = "https://www.hybrid-analysis.com/api/v2"

@retry(stop=stop_after_attempt(5), wait=wait_exponential())
def scan_hybrid_analysis(filepath, api_key):
    headers = {"api-key": api_key, "user-agent": "Falcon Sandbox"}
    
    # Quick scan (free tier)
    with open(filepath, 'rb') as f:
        files = {'file': f}
        params = {"environment_id": 120}  # Windows 10
        resp = requests.post(f"{HA_BASE}/quick-scan/file", headers=headers, files=files, data=params)
    
    if resp.status_code != 200:
        raise Exception(f"HA error: {resp.text}")
    
    quick_id = resp.json()["quick_scan_id"]
    
    # Poll report
    while True:
        report = requests.get(f"{HA_BASE}/quick-scan/{quick_id}", headers=headers)
        if report.status_code == 200 and report.json().get("is_finished"):
            return report.json()
        time.sleep(20)
