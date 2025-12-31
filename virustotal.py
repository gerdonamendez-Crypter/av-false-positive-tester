# virustotal.py
import time
import requests
from tenacity import retry, stop_after_attempt, wait_exponential
from .core import sha256_file

VT_API_BASE = "https://www.virustotal.com/api/v3"

@retry(stop=stop_after_attempt(5), wait=wait_exponential())
def _vt_request(method, url, api_key, **kwargs):
    headers = {"x-apikey": api_key}
    resp = requests.request(method, url, headers=headers, **kwargs)
    resp.raise_for_status()
    return resp.json()

def scan_file_with_virustotal(filepath, api_key):
    file_hash = sha256_file(filepath)

    try:
        return _vt_request("GET", f"{VT_API_BASE}/files/{file_hash}", api_key)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 404:
            raise

    # Upload
    with open(filepath, 'rb') as f:
        upload_resp = _vt_request("POST", f"{VT_API_BASE}/files", api_key, files={"file": f})
    analysis_id = upload_resp["data"]["id"]

    # Poll until complete
    while True:
        analysis = _vt_request("GET", f"{VT_API_BASE}/analyses/{analysis_id}", api_key)
        status = analysis["data"]["attributes"]["status"]
        if status == "completed":
            return _vt_request("GET", f"{VT_API_BASE}/files/{file_hash}", api_key)
        time.sleep(15)
