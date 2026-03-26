import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin


class HTMLDependencyExtractor:
    def __init__(self, timeout=3):
        self.timeout = timeout

    def fetch_html(self, domain: str) -> str:
        try:
        # Try HTTPS first
         url = f"https://{domain}"
         response = requests.get(url, timeout=self.timeout)
         return response.text
        except Exception:
         try:
            # Fallback to HTTP
            url = f"http://{domain}"
            response = requests.get(url, timeout=self.timeout)
            return response.text
         except Exception:
            return ""

    def extract_domains(self, domain: str) -> set:
        html = self.fetch_html(domain)
        if not html:
            return set()

        soup = BeautifulSoup(html, "html.parser")
        domains = set()

        # Extract from <script src="">
        for script in soup.find_all("script", src=True):
            full_url = urljoin(f"http://{domain}", script["src"])
            domains.add(self._get_domain(full_url))

        # Extract from <link href="">
        for link in soup.find_all("link", href=True):
            full_url = urljoin(f"http://{domain}", link["href"])
            domains.add(self._get_domain(full_url))

        # Extract from <img src="">
        for img in soup.find_all("img", src=True):
            full_url = urljoin(f"http://{domain}", img["src"])
            domains.add(self._get_domain(full_url))

        # Remove None / empty
        return {d for d in domains if d and d != domain}

    def _get_domain(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return None