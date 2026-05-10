# virustotal.py  (suggested replacement / enhancement)

import os
import time
import requests
import hashlib
from typing import Dict, Optional

class VirusTotalScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self.base_url = "https://www.virustotal.com/api/v3"
 
    def get_file_hash(self, filepath: str) -> str:
        """Compute SHA256 hash"""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_report_by_hash(self, file_hash: str) -> Optional[Dict]:
        """Check if report already exists"""
        url = f"{self.base_url}/files/{file_hash}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
            if resp.status_code == 200:
                print("[VT] Report found in cache.")
                return resp.json()
            elif resp.status_code == 404:
                return None
            else:
                print(f"[VT] API error: {resp.status_code} - {resp.text[:200]}")
                return None
        except Exception as e:
            print(f"[VT] Request failed: {e}")
            return None

    def upload_and_analyze(self, filepath: str, max_polling_time: int = 300) -> Dict:
        """Upload file (supports large files) and poll for result"""
        print(f"[VT] Uploading {os.path.basename(filepath)} ...")
        url = f"{self.base_url}/files"
        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            resp = requests.post(url, headers=self.headers, files=files, timeout=60)

        if resp.status_code not in (200, 201):
            raise RuntimeError(f"Upload failed: {resp.status_code} - {resp.text[:300]}")
 
        analysis_id = resp.json()["data"]["id"]
        print(f"[VT] Upload successful. Analysis ID: {analysis_id}")

        # Better polling with exponential backoff
        start = time.time()
        while time.time() - start < max_polling_time:
            result_url = f"{self.base_url}/analyses/{analysis_id}"
            resp = requests.get(result_url, headers=self.headers, timeout=15)

            if resp.status_code == 200:
                data = resp.json()
                status = data["data"]["attributes"]["status"]
                if status == "completed":
                    print("[VT] Analysis completed.")
                    return data
                elif status in ("queued", "in_progress"):
                    print(f"[VT] Status: {status} ... waiting")
                else:
                    print(f"[VT] Unexpected status: {status}")
            else:
                print(f"[VT] Poll error: {resp.status_code}")

            time.sleep(15)  # VT free tier usually needs ~15–60s

        raise TimeoutError("Analysis did not complete in time.")

    def scan(self, filepath: str) -> Dict:
        """Main entry point: check → upload if needed → return full report"""
        file_hash = self.get_file_hash(filepath)
        report = self.get_report_by_hash(file_hash)

        if report is None:
            report = self.upload_and_analyze(filepath)

        return {
            "sha256": file_hash,
            "size_bytes": os.path.getsize(filepath),
            "virustotal": report,
        }
