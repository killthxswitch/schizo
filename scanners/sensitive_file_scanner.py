import requests

from urllib.parse import urljoin

class SensitiveFileScanner:
    """Scanner for detecting exposed sensitive files."""

    def __init__(self, base_url):
        self.base_url = base_url
        self.files_to_check = [".git/config", ".env", "Dockerfile"]

    def scan_sensitive_files(self):
        """Scan for a list of sensitive files."""
        results = {}
        for file in self.files_to_check:
            file_url = urljoin(self.base_url, file)
            try:
                response = requests.get(file_url, timeout=5)
                if response.status_code == 200:
                    print(f"[!] Exposed {file} found at {file_url}")
                    results[file] = response.text
                else:
                    print(f"[+] No exposed {file} at {file_url}")
            except requests.RequestException as e:
                print(f"[!] Error scanning {file_url}: {e}")
        return results
