# metadefender.py
import requests
from tenacity import retry, stop_after_attempt, wait_exponential

BASE_URL = "https://api.metadefender.com/v4"
 
@retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=4, max=30))
def scan_metadefender(filepath, api_key):
    headers = {"apikey": api_key}
    
    # Upload
    with open(filepath, 'rb') as f:
        resp = requests.post(f"{BASE_URL}/file", headers=headers, files={"file": f})
    if resp.status_code != 200:
        raise Exception(f"Upload failed: {resp.text}")
    
    data_id = resp.json()["data_id"]
    
    # Poll until processed
    while True:
        report = requests.get(f"{BASE_URL}/file/{data_id}", headers=headers)
        if report.status_code == 200:
            json = report.json()
            if json["process_info"]["progress_percentage"] == 100:
                return json
        time.sleep(10)
