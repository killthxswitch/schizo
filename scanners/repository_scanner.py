import asyncio
import httpx
from urllib.parse import urljoin

class RepositoryScannerAsync:
    """Async scanner for discovering repositories with publicly accessible configuration files."""

    def __init__(self, base_url, timeout=5, max_content_length=500):
        self.base_url = base_url
        self.files_to_check = [".git/config", ".env", "Dockerfile"]
        self.timeout = timeout
        self.max_content_length = max_content_length

    async def scan_file(self, file, client):
        """Scan a single file for exposure."""
        file_url = urljoin(self.base_url, file)
        try:
            response = await client.get(file_url)
            print(f"DEBUG: Scanning {file_url}, Status: {response.status_code}")
            if response.status_code == 200:
                content = response.text[:self.max_content_length]  # Truncate content
                print(f"[!] Exposed {file} found at {file_url}")
                return file, {"status": response.status_code, "content": content, "error": None}
            else:
                print(f"[+] No exposed {file} at {file_url}")
                return file, {"status": response.status_code, "content": None, "error": None}
        except httpx.RequestError as e:
            print(f"[!] Error scanning {file_url}: {str(e)}")
            return file, {"status": "Error", "content": None, "error": str(e)}

    async def scan_sensitive_files(self):
        """Scan for a list of sensitive files."""
        results = {}
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            tasks = [self.scan_file(file, client) for file in self.files_to_check]
            responses = await asyncio.gather(*tasks)
            for file, result in responses:
                results[file] = result
        return results
