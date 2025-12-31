# virustotal.py (add large file support)
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
    file_size = os.path.getsize(filepath)

    # Check if already analysed
    try:
        return _vt_request("GET", f"{VT_API_BASE}/files/{file_hash}", api_key)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 404:
            raise

    # Upload
    if file_size > 32 * 1024 * 1024:  # >32MB
        upload_url = _vt_request("GET", f"{VT_API_BASE}/files/upload_url", api_key)["data"]
    else:
        upload_url = f"{VT_API_BASE}/files"

    with open(filepath, 'rb') as f:
        resp = _vt_request("POST", upload_url, api_key, files={"file": f})

    analysis_id = resp["data"]["id"]

    # Poll
    while True:
        analysis = _vt_request("GET", f"{VT_API_BASE}/analyses/{analysis_id}", api_key)
        if analysis["data"]["attributes"]["status"] == "completed":
            return _vt_request("GET", f"{VT_API_BASE}/files/{file_hash}", api_key)
        time.sleep(15)
